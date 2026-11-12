import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { collectRepository } from '../scripts/prepare-ciberia-repository-config.mjs';
import { buildReport, renderMarkdown, verifyLockfiles, main } from '../scripts/build-ciberia-offline-report.mjs';

const input = fileURLToPath(new URL('../examples/offline-frame.json', import.meta.url));
const repository = fileURLToPath(new URL('../examples/repository', import.meta.url));
const temporary = t => { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ciberia-report-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir; };

test('offline report hashes the exact input and covers every synthetic component', () => {
  const plan = buildReport({ input });
  assert.equal(plan.provenance.sha256, createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
  assert.equal(plan.provenance.source, 'offline-frame.json');
  assert.equal(plan.components.length, 2);
  assert.equal(plan.highCriticalPackageFindings.length, 4);
  assert.equal(plan.executionPolicy.externalRequests, 0);
  assert.equal(plan.executionPolicy.emailsSent, 0);
  assert.equal(plan.executionPolicy.changesAppliedToRepositories, false);
  for (const component of plan.components) assert.ok(renderMarkdown(plan).includes('| ' + component.package + ' |'));
});
test('n8n single-item JSON exports are accepted as data', t => {
  const file = path.join(temporary(t), 'n8n.json');
  fs.writeFileSync(file, JSON.stringify([{ json: JSON.parse(fs.readFileSync(input)) }]));
  assert.equal(buildReport({ input: file }).components.length, 2);
});
test('optional lock verification preserves hashes and rejects changed files', t => {
  const root = path.join(temporary(t), 'repository');
  fs.cpSync(repository, root, { recursive: true });
  const inventory = collectRepository({ root, id: 'demo', project: 'Demo' });
  assert.equal(verifyLockfiles(inventory, root).length, 2);
  fs.appendFileSync(path.join(root, 'composer.lock'), '\n');
  assert.throws(() => verifyLockfiles(inventory, root), /mudou/);
});
test('optional verification rejects traversal and symbolic links outside root', t => {
  const dir = temporary(t), root = path.join(dir, 'repository'); fs.mkdirSync(root);
  fs.copyFileSync(path.join(repository, 'composer.lock'), path.join(dir, 'composer.lock'));
  assert.throws(() => verifyLockfiles({ sourceFiles: [{ path: '../composer.lock' }] }, root), /fora de root/);
  fs.symlinkSync(path.join(dir, 'composer.lock'), path.join(root, 'composer.lock'));
  assert.throws(() => verifyLockfiles({ sourceFiles: [{ path: 'composer.lock' }] }, root), /fora de root/);
  assert.throws(() => buildReport({ input, root }), /usados juntos/);
});
test('CLI creates new JSON and Markdown and refuses to replace prior reports', t => {
  const output = path.join(temporary(t), 'report');
  main(['--input', input, '--output-dir', output]);
  const before = fs.readFileSync(path.join(output, 'plan.json'));
  assert.ok(fs.readFileSync(path.join(output, 'plan.md'), 'utf8').includes('plano offline'));
  assert.throws(() => main(['--input', input, '--output-dir', output]), /ja existe/);
  assert.deepEqual(fs.readFileSync(path.join(output, 'plan.json')), before);
});
test('input strings are never executed, and report cells escape HTML', t => {
  const dir = temporary(t), file = path.join(dir, 'input.json'), frame = JSON.parse(fs.readFileSync(input));
  frame.untrustedCode = 'throw new Error("must never execute")';
  frame.assets[0].id = '<script>example</script>|demo';
  for (const m of frame.osvMatches) for (const target of m.targets) target.assetId = frame.assets[0].id;
  fs.writeFileSync(file, JSON.stringify(frame));
  const markdown = renderMarkdown(buildReport({ input: file }));
  assert.ok(!markdown.includes('<script>'));
  assert.ok(markdown.includes('&lt;script&gt;'));
});
