import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildWorkflow } from '../../scripts/build-ciberia-v2.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const workflow = JSON.parse(fs.readFileSync(path.join(root, 'workflows/ciberia.json'), 'utf8'));
const nodes = new Map(workflow.nodes.map(n => [n.name, n]));
const now = '2020-10-28T12:00:00.000Z';
const clone = x => JSON.parse(JSON.stringify(x));
const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/synthetic-php-advisories.json', import.meta.url)));
const config = { maxInventoryAgeHours: 168, reminderHours: 168, newsLookbackDays: 30, maxQueries: 10000, maxDetails: 500, includeDev: false, dryRun: true, useAI: true, recipient: 'security@example.invalid' };
const asset = (id = 'A', version = '8.4.0', extra = {}) => ({ id, project: 'Projeto ' + id, environment: 'synthetic-lab', evidenceType: 'runtime', observedAt: now, php: { version, distribution: 'upstream', sapi: 'fpm-fcgi' }, packages: [], ...extra });
const frame = (assets = [asset()], extra = {}) => ({ config: clone(config), assets, generatedAt: now, demo: false, manual: false, dryRun: true, issues: [], failures: [], phpAdvisories: clone(fixture), news: [], osvMatches: [], details: [], ...extra });

function run(name, json, { refs = {}, mode = 'test', state = {}, paired = [] } = {}) {
  const input = (Array.isArray(json) ? json : [json]).map(j => ({ json: clone(j) }));
  const context = {
    $input: { first: () => input[0], all: () => input },
    $execution: { mode },
    $getWorkflowStaticData: () => state,
    $: key => ({
      first: () => ({ json: clone(refs[key][0]) }),
      all: () => refs[key].map(json => ({ json: clone(json) })),
      itemMatching: index => ({ json: clone(refs[key][paired[index] ?? index]) }),
    }),
    console: { log() {} },
  };
  const result = new vm.Script('(function(){\n' + nodes.get(name).parameters.jsCode + '\n})()', { filename: name }).runInNewContext(context, { timeout: 2500 });
  return clone(result).map(i => i.json);
}
const analyze = f => run('Avaliar evidencias', f)[0];
const render = (f, state = {}) => run('Deduplicar e montar email', f, { state })[0];
function normalize(f, jobs, responses, paired = []) {
  const entries = responses.map((response, i) => ({ job: jobs[paired[i] ?? i], response }));
  const getJobs = jobs.filter(j => j.kind !== 'osv');
  const context = { ...f, jobs, osvResponses: entries.filter(x => x.job.kind === 'osv') };
  const getEntries = entries.filter(x => x.job.kind !== 'osv');
  return run('Normalizar fontes', getEntries.map(x => x.response), {
    refs: { 'Preparar consultas GET': getJobs.map(j => ({ ...j, frame: context })) },
    paired: getEntries.map(x => getJobs.indexOf(x.job)),
  })[0];
}

test('community export has safe defaults, no credentials and no execution retention', () => {
  const c = run('Configuracao', {}, { mode: 'production' })[0];
  assert.equal(workflow.name, 'CIBERIA — Community');
  assert.equal(c.config.dryRun, true);
  assert.equal(c.config.demoOnManual, true);
  assert.equal(c.config.useAI, false);
  assert.equal(c.config.recipient, 'demo@example.invalid');
  assert.deepEqual(c.assets, []);
  assert.equal(workflow.active, false);
  assert.equal(workflow.settings.saveDataErrorExecution, 'none');
  assert.equal(workflow.settings.saveDataSuccessExecution, 'none');
  assert.equal(workflow.settings.saveManualExecutions, false);
  assert.deepEqual(workflow.pinData, {});
  assert.deepEqual(workflow.tags, []);
  for (const n of workflow.nodes) assert.equal(Object.hasOwn(n, 'credentials'), false);
  for (const name of ['Explicar com Gemini', 'Enviar um unico email']) {
    assert.equal(nodes.get(name).disabled, true);
  }
  assert.equal(nodes.get('Explicar com Gemini').parameters.modelId.value, '');
  const exported = JSON.stringify(workflow);
  assert.doesNotMatch(exported, /CVE-\d{4}-\d+|\/(?:home|Users)\/|Downloads/);
});

test('builder is reproducible and the committed export matches its output', () => {
  const first = JSON.stringify(buildWorkflow(), null, 2) + '\n';
  const second = JSON.stringify(buildWorkflow(), null, 2) + '\n';
  assert.equal(first === second, true, 'builds must be byte-for-byte identical');
  assert.equal(first === fs.readFileSync(path.join(root, 'workflows/ciberia.json'), 'utf8'), true, 'regenerate workflows/ciberia.json after builder changes');
});

test('export is inactive, acyclic, unique IDs, valid code and linked nodes', () => {
  assert.equal(workflow.active, false);
  assert.equal(workflow.settings.timezone, 'UTC');
  assert.equal(nodes.size, workflow.nodes.length);
  assert.equal(new Set(workflow.nodes.map(n => n.id)).size, workflow.nodes.length);
  for (const n of nodes.values()) if (n.type === 'n8n-nodes-base.code') new vm.Script('(function(){' + n.parameters.jsCode + '})()');
  const edges = new Map();
  for (const [source, connections] of Object.entries(workflow.connections)) {
    assert.ok(nodes.has(source));
    for (const [output, group] of connections.main.entries()) for (const edge of group || []) {
      assert.ok(nodes.has(edge.node)); assert.equal(edge.type, 'main'); assert.equal(edge.index, 0);
      if (nodes.get(source).type === 'n8n-nodes-base.if') assert.ok(output < 2);
      edges.set(source, [...(edges.get(source) || []), edge.node]);
    }
  }
  function visit(name, ancestors = new Set()) { assert.ok(!ancestors.has(name), 'Ciclo: ' + name); for (const to of edges.get(name) || []) visit(to, new Set([...ancestors, name])); }
  visit('Testar sem email'); visit('A cada hora');
  const senders = workflow.nodes.filter(n => n.type === 'n8n-nodes-base.gmail');
  assert.equal(senders.length, 1);
  assert.deepEqual(workflow.connections['Enviar um unico email'].main[0].map(e => e.node), ['Confirmar envio e salvar estado']);
  assert.ok(!workflow.nodes.some(n => /webhook|executeCommand|ssh/i.test(n.type)));
});

test('all pure n8n expressions parse; GitHub pagination is allowlisted', () => {
  const expressions = [];
  function walk(value) { if (typeof value === 'string' && value.startsWith('={{') && value.endsWith('}}')) expressions.push(value.slice(3, -2)); else if (Array.isArray(value)) value.forEach(walk); else if (value && typeof value === 'object') Object.values(value).forEach(walk); }
  walk(workflow);
  for (const expr of expressions) new vm.Script('(' + expr + ')');
  const pagination = nodes.get('Consultar fontes').parameters.options.pagination.pagination;
  assert.equal(nodes.get('Consultar fontes').parameters.sendBody, false);
  assert.equal(nodes.get('Consultar fontes').parameters.method, 'GET');
  assert.equal(nodes.get('Consultar lotes OSV').parameters.contentType, 'json');
  assert.equal(nodes.get('Consultar lotes OSV').parameters.sendBody, true);
  assert.equal(nodes.get('Consultar lotes OSV').parameters.method, 'POST');
  const evaluate = (exp, headers) => new vm.Script('(' + exp.slice(3, -2) + ')').runInNewContext({ $response: { headers } });
  const next = 'https://api.github.com/repos/php/php-src/security-advisories?per_page=100&after=abc';
  assert.equal(evaluate(pagination.nextURL, { link: '<' + next + '>; rel="next", <https://api.github.com/x>; rel="prev"' }), next);
  assert.equal(evaluate(pagination.completeExpression, {}), true);
  assert.throws(() => evaluate(pagination.nextURL, { link: '<https://attacker.invalid/>; rel="next"' }), /fora da fonte/);
});

test('manual demo is offline and preview-only, with no state mutation', () => {
  const state = {};
  const c = run('Configuracao', {}, { mode: 'test' })[0];
  assert.equal(c.demo, true); assert.equal(c.dryRun, true);
  const demo = run('Cenario PHP seguro', c)[0];
  const result = render(analyze(demo), state);
  assert.equal(result.shouldSend, false); assert.equal(result.useAI, false);
  assert.equal(result.findings.filter(x => x.status === 'AFETADO_POR_VERSAO').length, 4);
  assert.equal(result.assessed.filter(x => x.assetId === 'demo-outside-range').length, 2);
  assert.equal(result.findings.filter(x => x.assetId === 'demo-unknown-line').length, 2);
  assert.equal(result.findings.filter(x => x.status === 'BOLETIM_REQUER_ANALISE').length, 1);
  assert.ok(result.findings.every(x => x.id.startsWith('DEMO-')));
  assert.ok(result.findings.every(x => x.sources.every(url => new URL(url).hostname === 'example.invalid')));
  assert.ok(!result.html.includes('Advisory oficial'));
  assert.deepEqual(state, {});
});

test('unconfigured production reports coverage problem and remains dry-run', () => {
  const c = run('Configuracao', {}, { mode: 'production' })[0];
  assert.equal(c.demo, false); assert.equal(c.dryRun, true); assert.equal(c.assets.length, 0);
  const report = analyze({ ...c, phpAdvisories: [], news: [], failures: [], osvMatches: [], details: [] });
  assert.equal(report.totals.coverageProblems, 1);
});

test('exact PHP release line, patch boundaries and multiple assets', () => {
  const f = analyze(frame([asset('A'), asset('B'), asset('C', '8.4.1')]));
  assert.equal(f.findings.length, 4);
  assert.equal(new Set(f.findings.map(x => x.key)).size, 4);
  assert.ok(f.findings.every(x => x.fixed.join() === '8.4.1'));
  assert.equal(f.assessed.length, 2);
  for (const [vulnerable, fixed] of [['8.2.0', '8.2.1'], ['8.3.0', '8.3.1'], ['8.5.0', '8.5.1']]) {
    assert.equal(analyze(frame([asset('A', vulnerable)])).findings.length, 2);
    assert.equal(analyze(frame([asset('A', fixed)])).findings.length, 0);
  }
});

test('legacy, vendor backport, stale inventory and repository PHP stay inconclusive', () => {
  for (const a of [
    asset('A', '7.4.0'), asset('A', '8.4.0-1'),
    asset('A', '8.4.0', { evidenceType: 'repository' }),
    asset('A', '8.4.0', { php: { version: '8.4.0', distribution: 'vendor' } }),
    asset('A', '8.4.0', { php: { version: '8.4.0', distribution: 'upstream', vendorBackports: [{ id: fixture[0].ghsa_id, evidenceUrl: 'https://example.invalid/vendor-advisory' }] } }),
    asset('A', '8.4.0', { observedAt: '2020-01-01T00:00:00Z' }),
  ]) {
    const report = analyze(frame([a]));
    assert.equal(report.findings.find(x => x.id === fixture[0].ghsa_id).status, 'POTENCIAL_REQUER_ANALISE');
  }
  const f = analyze(frame([asset('A', '8.4.0', { observedAt: undefined })]));
  assert.ok(f.findings.some(x => x.status === 'COBERTURA_INCOMPLETA'));
});

test('old official PHP records with blank/other ecosystem are not silently dropped', () => {
  const advisory = clone(fixture[0]);
  advisory.vulnerabilities.forEach(v => { v.package = { ecosystem: '', name: '' }; });
  let f = analyze(frame([asset()], { phpAdvisories: [advisory] }));
  assert.equal(f.findings.length, 1); assert.equal(f.findings[0].status, 'POTENCIAL_REQUER_ANALISE');
  advisory.vulnerabilities.forEach(v => { v.package = { ecosystem: 'other', name: 'php-src' }; });
  f = analyze(frame([asset()], { phpAdvisories: [advisory] }));
  assert.equal(f.findings[0].status, 'AFETADO_POR_VERSAO');
});

test('extension and unknown PHP range conditions never produce confirmed engine impact', () => {
  const a = clone(fixture[0]); a.vulnerabilities.forEach(v => { v.package.name = 'ext-soap'; });
  const f = analyze(frame([asset()], { phpAdvisories: [a] }));
  assert.equal(f.findings[0].status, 'POTENCIAL_REQUER_ANALISE');
  const without = asset(); without.php.extensions = ['curl', 'session'];
  assert.equal(analyze(frame([without], { phpAdvisories: [a] })).findings.length, 0);
  a.vulnerabilities.forEach(v => { v.package.name = 'php-src'; v.vulnerable_version_range = '^8.4'; });
  assert.equal(analyze(frame([asset()], { phpAdvisories: [a] })).findings[0].status, 'POTENCIAL_REQUER_ANALISE');
});

test('official notices stay conditional even with patched PHP', () => {
  const f = analyze(frame([asset('A', '8.4.1')], { news: [{ id: 'news:1', title: 'Session upload progress', published: now, text: 'Condicao incomum: serialize handler alterado por codigo.', url: 'https://www.php.net/archive/2020.php#2020-10-23-1' }] }));
  assert.equal(f.findings.length, 1); assert.equal(f.findings[0].status, 'BOLETIM_REQUER_ANALISE');
  assert.deepEqual(f.findings[0].fixed, []);
});

test('queries deduplicate identical packages across assets, preserve targets and exclude dev', () => {
  const p = { ecosystem: 'Packagist', name: 'demo/framework', version: '11.0.0', dev: false };
  const f = frame([asset('A', '8.4.1', { packages: [p, { ecosystem: 'npm', name: 'dev-dep', version: '1.0.0', dev: true }] }), asset('B', '8.4.1', { packages: [p] })]);
  const jobs = run('Preparar consultas', f);
  const osv = jobs.find(j => j.kind === 'osv'); assert.equal(osv.queries.length, 1); assert.equal(osv.queries[0].targets.length, 2);
  assert.equal(osv.payload.queries[0].package.ecosystem, 'Packagist');
});

test('OSV batch matching resolves details, severity, aliases and transitive targets', () => {
  const p = { ecosystem: 'npm', name: 'demo-client', version: '0.21.0', dev: false };
  const f = frame([asset('A', '8.4.1', { packages: [p] }), asset('B', '8.4.1', { packages: [p] })], { phpAdvisories: [] });
  const jobs = run('Preparar consultas', f);
  const responses = jobs.map(j => ({ statusCode: 200, headers: {}, body: j.kind === 'osv' ? JSON.stringify({ results: [{ vulns: [{ id: 'DEMO-OSV-001', modified: now }] }] }) : j.kind === 'php' ? '[]' : '<article class="newsItem"><time datetime="2020-10-28T00:00:00Z"></time><h2><a href="https://www.php.net/archive/2020.php#test">Security notice</a></h2>Review configuration</article>' }));
  const normalized = normalize(f, jobs, responses);
  assert.equal(normalized.needsDetails, true); assert.equal(normalized.osvMatches[0].targets.length, 2);
  assert.equal(normalized.news.length, 1);
  const detailJobs = run('Preparar detalhes OSV', normalized);
  const detail = { id: detailJobs[0].id, aliases: ['DEMO-OSV-001'], modified: now, summary: 'Example test advisory', database_specific: { severity: 'HIGH' }, affected: [{ package: { ecosystem: 'npm', name: 'demo-client' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.21.1' }] }] }], references: [{ url: 'https://example.invalid/advisories/DEMO-OSV-001' }] };
  const detailed = run('Normalizar detalhes', { statusCode: 200, body: JSON.stringify(detail) }, { refs: { 'Normalizar fontes': [normalized], 'Preparar detalhes OSV': detailJobs } })[0];
  const report = analyze(detailed);
  const vulnerabilities = report.findings.filter(x => x.ecosystem === 'npm');
  assert.equal(vulnerabilities.length, 2); assert.ok(vulnerabilities.every(x => x.id === 'DEMO-OSV-001' && x.severity === 'high'));
  assert.deepEqual(vulnerabilities[0].fixed, ['0.21.1']);
});

test('aliases of one synthetic CVE preserve the highest severity and every source regardless of order', () => {
  const p = { ecosystem: 'npm', name: 'demo-library', version: '1.0.0', dev: false };
  // Fictional alias solely to exercise CVE canonicalization; not a real advisory.
  const alias = 'CVE-2099-0001';
  const details = ['MEDIUM', 'HIGH'].map((severity, i) => ({
    id: 'DEMO-ALIAS-' + i, aliases: [alias], modified: now,
    summary: 'Synthetic alias ' + i, database_specific: { severity },
    affected: [{ package: { ecosystem: p.ecosystem, name: p.name }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: ['1.0.2', '1.1.0'][i] }] }] }],
    references: [{ url: 'https://example.invalid/advisories/DEMO-ALIAS-' + i }],
  }));
  const matches = details.map(d => ({ id: d.id, targets: [{ assetId: 'A', package: p }] }));
  const reports = [matches, [...matches].reverse()].map(osvMatches => analyze(frame([asset('A', '8.4.1', { packages: [p] })], { phpAdvisories: [], details, osvMatches })));
  for (const report of reports) {
    assert.equal(report.findings.length, 1);
    assert.equal(report.findings[0].severity, 'high');
    assert.deepEqual(report.findings[0].fixed, ['1.0.2', '1.1.0']);
    assert.deepEqual(report.findings[0].aliases, [alias, 'DEMO-ALIAS-0', 'DEMO-ALIAS-1']);
    assert.ok(report.findings[0].sources.includes(details[0].references[0].url));
    assert.ok(report.findings[0].sources.includes(details[1].references[0].url));
  }
  assert.deepEqual(reports[0].findings, reports[1].findings);
});

test('HTTP errors, changed HTML and OSV pagination are visible coverage failures', () => {
  const f = frame([asset()], { phpAdvisories: [] });
  const p = { ecosystem: 'npm', name: 'test', version: '1.0.0' }; f.assets[0].packages = [p];
  const jobs = run('Preparar consultas', f);
  const responses = jobs.map(j => j.kind === 'osv' ? { statusCode: 200, body: JSON.stringify({ results: [{ vulns: [], next_page_token: 'next' }] }) } : j.kind === 'php' ? { statusCode: 403, body: 'rate limited' } : { statusCode: 200, body: '<h1>unexpected</h1>' });
  const normalized = normalize(f, jobs, responses);
  assert.equal(normalized.failures.length, 3);
  assert.equal(analyze(normalized).totals.coverageProblems, 3);
});

test('pagination/item linking is not confused with output order', () => {
  const f = frame();
  const jobs = [ { kind: 'php', url: 'https://api.github.com/repos/php/php-src/security-advisories' }, { kind: 'news', url: 'https://www.php.net/archive/2020.php' } ];
  const responses = [{ statusCode: 200, body: JSON.stringify([fixture[0]]), headers: { link: '<https://api.github.com/repos/php/php-src/security-advisories?after=abc>; rel="next"' } }, { statusCode: 200, body: JSON.stringify([fixture[1]]), headers: {} }, { error: 'timeout' }];
  const normalized = normalize(f, jobs, responses, [0, 0, 1]);
  assert.equal(normalized.phpAdvisories.length, 2); assert.equal(normalized.failures.length, 1);
});

test('dedup only advances after Gmail confirmation; repeat, change and reminder behavior', () => {
  const state = {};
  const f = analyze(frame([asset('A')], { dryRun: false }));
  let message = render(f, state);
  assert.equal(message.shouldSend, true); assert.equal(message.findings.length, 2); assert.deepEqual(state, {});
  assert.throws(() => run('Confirmar envio e salvar estado', { error: 'no send' }, { refs: { 'Finalizar email': [message] }, state }), /Gmail nao confirmou/);
  assert.deepEqual(state, {});
  const ack = run('Confirmar envio e salvar estado', { id: 'test-not-a-real-email' }, { refs: { 'Finalizar email': [message] }, state })[0];
  assert.equal(ack.status, 'EMAIL_CONFIRMADO'); assert.equal(Object.keys(state.ciberiaV2.ledger).length, 2);
  assert.equal(render(f, state).findings.length, 0);
  const updated = clone(f); updated.findings[0].revision = 'changed';
  assert.equal(render(updated, state).findings.length, 1);
  const later = clone(f); later.generatedAt = '2020-11-05T12:00:00Z';
  message = render(later, state); assert.equal(message.findings.length, 2); assert.ok(message.findings.every(x => x.notification === 'LEMBRETE'));
});

test('reintroduced same vulnerable version not suppressed after complete clean scan', () => {
  const state = {};
  const affected = analyze(frame([asset()], { dryRun: false }));
  const message = render(affected, state);
  run('Confirmar envio e salvar estado', { id: 'test' }, { refs: { 'Finalizar email': [message] }, state });
  const clean = render(analyze(frame([asset('A', '8.4.1')], { dryRun: false })), state);
  run('Resultado sem envio', clean, { state });
  assert.equal(Object.keys(state.ciberiaV2.ledger).length, 0);
  assert.equal(render(affected, state).findings.length, 2);
});

test('coverage failure does not clear existing notification ledger', () => {
  const state = { ciberiaV2: { ledger: { old: { fingerprint: 'old', sentAt: 1 } } } };
  run('Resultado sem envio', { dryRun: false, totals: { coverageProblems: 1 }, activeKeys: [], findings: [] }, { state });
  assert.ok(state.ciberiaV2.ledger.old);
});

test('AI failure preserves full deterministic report; HTML/AI injection is escaped', () => {
  const f = analyze(frame([asset()], { dryRun: false }));
  f.findings[0].title = '<img src=x onerror=alert(1)>'; f.findings[0].sources.push('javascript:alert(1)');
  const message = render(f);
  assert.ok(message.html.includes('&lt;img')); assert.ok(!message.html.includes('href="javascript:'));
  let final = run('Finalizar email', { error: 'Gemini down' }, { refs: { 'Deduplicar e montar email': [message] } })[0];
  assert.ok(final.html.includes('indisponivel')); assert.equal(final.findings.length, message.findings.length);
  final = run('Finalizar email', { content: { parts: [{ text: '<script>malicious()</script>' }] } }, { refs: { 'Deduplicar e montar email': [message] } })[0];
  assert.ok(final.html.includes('&lt;script&gt;')); assert.ok(!final.html.includes('<script>'));
  assert.ok(!message.aiFacts.includes('Projeto A'));
});

test('dry-run notification acknowledgement is rejected', () => {
  const message = render(analyze(frame()));
  assert.throws(() => run('Confirmar envio e salvar estado', { id: 'test' }, { refs: { 'Finalizar email': [message] } }), /Protecao/);
});

test('editor and unknown modes cannot send even when dryRun is disabled in config', () => {
  const n = nodes.get('Configuracao'); const before = n.parameters.jsCode;
  try {
    n.parameters.jsCode = before.replace('"dryRun": true', '"dryRun": false');
    for (const mode of ['test', 'manual', 'cli', 'unknown', undefined]) {
      const c = run('Configuracao', {}, { mode })[0];
      assert.equal(c.dryRun, true); assert.equal(c.demo, true);
    }
    assert.equal(run('Configuracao', {}, { mode: 'production' })[0].dryRun, false);
  } finally { n.parameters.jsCode = before; }
});

test('notification batch cap keeps deferred alerts eligible for the next run', () => {
  const state = {};
  const report = analyze(frame([asset('A'), asset('B')], { dryRun: false }));
  report.config.maxAlertsPerEmail = 2;
  let msg = render(report, state);
  assert.equal(msg.findings.length, 2); assert.equal(msg.deferred, 2); assert.equal(msg.suppressed, 0);
  run('Confirmar envio e salvar estado', { id: 'test-batch' }, { refs: { 'Finalizar email': [msg] }, state });
  msg = render(report, state);
  assert.equal(msg.findings.length, 2); assert.equal(msg.deferred, 0); assert.equal(msg.suppressed, 2);
});
