import fs from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { normalizeSeverity, compareVersions, rangeContains, packageAffected, chooseCandidates, buildOfflinePlan } from '../scripts/ciberia-offline-plan.mjs';

const fixture = () => JSON.parse(fs.readFileSync(new URL('../examples/offline-frame.json', import.meta.url)));
const row = (events, type = 'SEMVER') => ({ type, events });
const detail = (id, events, severity = 'HIGH') => ({ id, database_specific: { severity }, affected: [{ package: { name: 'demo', ecosystem: 'npm' }, ranges: [row(events)] }] });

test('severity normalization preserves high, critical and unknown', () => {
  assert.equal(normalizeSeverity('MODERATE'), 'medium');
  assert.equal(normalizeSeverity('CRITICAL'), 'critical');
  assert.equal(normalizeSeverity('HIGH'), 'high');
  assert.equal(normalizeSeverity('unexpected'), 'unknown');
});
test('version ordering handles prefixes and numeric prerelease identifiers conservatively', () => {
  assert.equal(compareVersions('v1.2.3', '1.2.3'), 0);
  assert.ok(compareVersions('2.0.0-alpha.13', '2.0.0-alpha.9') > 0);
  assert.ok(compareVersions('2.0.0-rc.1', '2.0.0') < 0);
  assert.equal(compareVersions('dev-main', '1.2.3'), null);
});
test('fixed and limit are exclusive, last_affected inclusive, separate ranges stay independent', () => {
  const ranges = row([{ introduced: '1.0.0' }, { fixed: '1.2.3' }, { introduced: '2.0.0' }, { fixed: '2.0.5' }]);
  assert.equal(rangeContains(ranges, '1.2.2'), true);
  assert.equal(rangeContains(ranges, '1.2.3'), false);
  assert.equal(rangeContains(ranges, '2.0.4'), true);
  assert.equal(rangeContains(ranges, '2.0.5'), false);
  assert.equal(rangeContains(row([{ introduced: '0' }, { last_affected: '1.2.3' }]), '1.2.3'), true);
  assert.equal(rangeContains(row([{ introduced: '0' }, { limit: '1.2.3' }]), '1.2.3'), false);
});
test('unsupported range bounds and Git ranges remain unknown', () => {
  assert.equal(rangeContains(row([{ introduced: '0' }, { fixed: 'dev-main' }]), '1.2.3'), null);
  assert.equal(rangeContains(row([{ introduced: 'abc' }], 'GIT'), '1.2.3'), null);
  assert.equal(rangeContains(row([]), '1.2.3'), null);
  assert.equal(compareVersions('999999999999999999999.0.0', '1.0.0'), null);
});
test('candidate must clear every high and critical advisory from the snapshot', () => {
  const ds = [detail('DEMO-1', [{ introduced: '0' }, { fixed: '1.0.2' }]), detail('DEMO-2', [{ introduced: '0' }, { fixed: '1.0.4' }])];
  const [target] = chooseCandidates(['1.0.0'], ds, 'npm', 'demo');
  assert.equal(target.candidate, '1.0.4');
  assert.ok(target.rejectedCandidates.some(c => c.version === '1.0.2' && c.remaining.includes('DEMO-2')));
});
test('no same-major fix invents no patch, but records a checked major alternative', () => {
  const [target] = chooseCandidates(['1.0.0'], [detail('DEMO-1', [{ introduced: '0' }, { fixed: '2.0.1' }])], 'npm', 'demo');
  assert.equal(target.candidate, null);
  assert.deepEqual(target.upgradeAlternatives, ['2.0.1']);
});
test('withdrawn advisories do not block candidates', () => {
  assert.equal(packageAffected({ ...detail('DEMO-1', [{ introduced: '0' }]), withdrawn: '2026-01-01' }, 'npm', 'demo', '1.0.0'), false);
});
test('synthetic export preserves every affected version and evidence boundaries', () => {
  const plan = buildOfflinePlan(fixture());
  assert.equal(plan.summary.allVersionsPackageHighCritical, 4);
  assert.equal(plan.components.length, 2);
  assert.equal(plan.summary.dataIssues, 0);
  const component = plan.components.find(c => c.package === 'demo-library');
  assert.deepEqual(component.installedVersions, ['1.0.0', '1.1.0']);
  assert.equal(component.targets[0].candidate, '1.1.3');
  assert.equal(component.compatibilityStatus, 'NAO_RESOLVIDA_PELO_GERENCIADOR');
  assert.equal(plan.byAsset[0].evidenceType, 'repository');
  assert.equal(plan.scope.emailBatchLimitApplied, false);
  assert.ok(plan.highCriticalPackageFindings.every(f => f.sources.every(s => s.startsWith('https://example.invalid/'))));
});
test('missing details and stale outside-range matches become data issues', () => {
  const frame = fixture();
  frame.osvMatches.push({ id: 'DEMO-MISSING', targets: [] });
  frame.osvMatches[0].targets.push({ assetId: 'demo-app', package: frame.assets[0].packages[1] });
  const plan = buildOfflinePlan(frame);
  assert.equal(plan.dataIssues.length, 2);
  assert.equal(plan.summary.allVersionsPackageHighCritical, 4);
});
test('targets outside the supplied inventory cannot create package findings', () => {
  const frame = fixture();
  frame.osvMatches[0].targets.push({ assetId: 'other', package: frame.assets[0].packages[0] });
  assert.equal(buildOfflinePlan(frame).dataIssues.length, 1);
  assert.throws(() => buildOfflinePlan({}), /Export sem/);
});
test('unsupported installed versions remain manual-review tasks, not empty successful plans', () => {
  const frame = fixture();
  frame.assets[0].packages[2].version = '2.0';
  frame.osvMatches[2].targets[0].package.version = '2.0';
  const component = buildOfflinePlan(frame).components.find(c => c.ecosystem === 'Packagist');
  assert.deepEqual(component.unsupportedInstalledVersions, ['2.0']);
  assert.equal(component.targets.length, 0);
  assert.equal(component.status, 'MIGRACAO_OU_BACKPORT_A_AVALIAR');
});
test('aliases of one fictional CVE preserve maximum severity and all evidence regardless of source order', () => {
  const frame = fixture(), pkg = frame.assets[0].packages[0];
  frame.assets[0].packages = [pkg];
  frame.details = [
    { ...detail('DEMO-MEDIUM', [{ introduced: '0' }, { fixed: '1.0.2' }], 'MEDIUM'), aliases: ['CVE-2099-0001', 'DEMO-ALIAS-M'], summary: 'Medium source', modified: '2026-01-01T00:00:00Z', references: [{ type: 'ADVISORY', url: 'https://example.invalid/medium' }], severity: [{ type: 'CVSS_V3', score: 'DEMO-MEDIUM-VECTOR' }], database_specific: { severity: 'MEDIUM', cwe_ids: ['CWE-20'] } },
    { ...detail('DEMO-HIGH', [{ introduced: '0' }, { fixed: '1.0.4' }], 'HIGH'), aliases: ['DEMO-ALIAS-H', 'CVE-2099-0001'], summary: 'High source', modified: '2026-01-02T00:00:00Z', references: [{ type: 'ADVISORY', url: 'https://example.invalid/high' }], severity: [{ type: 'CVSS_V3', score: 'DEMO-HIGH-VECTOR' }], database_specific: { severity: 'HIGH', cwe_ids: ['CWE-79'] } },
  ];
  for (const d of frame.details) d.affected[0].package.name = pkg.name;
  frame.osvMatches = frame.details.map(d => ({ id: d.id, targets: [{ assetId: frame.assets[0].id, package: pkg }] }));
  const forward = buildOfflinePlan(frame);
  frame.details.reverse(); frame.osvMatches.reverse();
  const reverse = buildOfflinePlan(frame);
  assert.equal(forward.summary.allVersionsPackageHighCritical, 1);
  assert.equal(reverse.summary.allVersionsPackageHighCritical, 1);
  assert.equal(forward.components.length, 1);
  assert.equal(forward.dataIssues.length, 0);
  assert.deepEqual(forward.highCriticalPackageFindings, reverse.highCriticalPackageFindings);
  assert.deepEqual(forward.components, reverse.components);
  const [finding] = forward.highCriticalPackageFindings;
  assert.equal(finding.id, 'CVE-2099-0001');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.osvId, 'DEMO-HIGH');
  assert.equal(finding.title, 'High source');
  assert.deepEqual(finding.osvIds, ['DEMO-HIGH', 'DEMO-MEDIUM']);
  assert.deepEqual(finding.aliases, ['CVE-2099-0001', 'DEMO-ALIAS-H', 'DEMO-ALIAS-M']);
  assert.deepEqual(finding.cwe, ['CWE-20', 'CWE-79']);
  assert.deepEqual(finding.fixed, ['1.0.2', '1.0.4']);
  assert.deepEqual(finding.sources, ['https://example.invalid/high', 'https://example.invalid/medium']);
  assert.equal(finding.cvssVectorsFromSource.length, 2);
  assert.equal(finding.advisoryEvidence.length, 2);
  assert.equal(forward.components[0].targets[0].candidate, '1.0.4');
});
test('same-severity canonical sources select metadata by source ID and duplicate source matches count once', () => {
  const frame = fixture(), pkg = frame.assets[0].packages[0];
  frame.assets[0].packages = [pkg];
  frame.details = ['DEMO-Z', 'DEMO-A'].map(id => ({ ...detail(id, [{ introduced: '0' }, { fixed: '1.0.2' }]), aliases: ['CVE-2099-0002'], summary: id }));
  for (const d of frame.details) d.affected[0].package.name = pkg.name;
  frame.osvMatches = [...frame.details, frame.details[0]].map(d => ({ id: d.id, targets: [{ assetId: frame.assets[0].id, package: pkg }] }));
  const plan = buildOfflinePlan(frame);
  assert.equal(plan.highCriticalPackageFindings.length, 1);
  assert.equal(plan.highCriticalPackageFindings[0].osvId, 'DEMO-A');
  assert.equal(plan.highCriticalPackageFindings[0].advisoryEvidence.length, 2);
  assert.equal(plan.highCriticalPackageFindings[0].title, 'DEMO-A');
});
