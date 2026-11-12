import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { isVersion, composerPackages, npmPackages, deduplicate, collectRepository, main } from '../scripts/prepare-ciberia-repository-config.mjs';

const example = fileURLToPath(new URL('../examples/repository', import.meta.url));
const temporary = t => { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ciberia-collect-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir; };

test('exact version labels are retained; constraints, branches and URLs stay unresolved', () => {
  for (const version of ['1.1', '2.0', 'v3.4.1', '1.2.3-beta.1']) assert.equal(isVersion(version), true);
  for (const version of ['^1.2', '1.2.*', 'dev-main', 'https://example.invalid/pkg', '>=2.0', '']) assert.equal(isVersion(version), false);
  const result = composerPackages({ packages: [{ name: 'demo/library', version: '2.0' }, { name: 'demo/branch', version: 'https://example.invalid/private', source: { reference: 'private-reference' } }] });
  assert.equal(result.packages[0].version, '2.0');
  assert.equal(result.unresolved.length, 1);
  assert.ok(!JSON.stringify(result).includes('private-reference'));
  assert.ok(!JSON.stringify(result).includes('https://example.invalid/private'));
});
test('npm aliases, nested scopes and links are handled without exporting download URLs', () => {
  const result = npmPackages({ lockfileVersion: 3, packages: {
    '': { name: 'demo-app', version: '1.0.0' },
    'node_modules/alias': { version: '1.2.3', resolved: 'https://registry.npmjs.org/demo-library/-/demo-library-1.2.3.tgz', dev: true },
    'node_modules/parent/node_modules/@demo/library': { version: '2.1.0' },
    'node_modules/linked': { link: true, resolved: 'packages/linked' },
  } });
  assert.deepEqual(result.packages.map(p => p.name), ['demo-library', '@demo/library']);
  assert.equal(result.unresolved.length, 1);
  assert.ok(result.packages.every(p => !Object.hasOwn(p, 'resolved')));
  assert.ok(!JSON.stringify(result).includes('registry.npmjs.org'));
  assert.throws(() => npmPackages({ lockfileVersion: 1, dependencies: {} }), /v2\/v3/);
});
test('dedup keeps multiple versions and non-dev/non-optional occurrences', () => {
  const result = deduplicate([
    { ecosystem: 'npm', name: 'demo', version: '1.0.0', dev: true, optional: true, devOptional: true },
    { ecosystem: 'npm', name: 'demo', version: '1.0.0', dev: false },
    { ecosystem: 'npm', name: 'demo', version: '2.0.0', dev: true },
  ]);
  assert.equal(result.length, 2); assert.equal(result[0].dev, false);
  assert.equal(result[0].optional, undefined); assert.equal(result[0].devOptional, undefined);
});
test('collector records synthetic lockfile hashes and relative paths, not source contents', () => {
  const inventory = collectRepository({ root: example, id: 'demo-app', project: 'Demo Application', observedAt: '2026-01-01T00:00:00Z' });
  assert.equal(inventory.summary.assets, 1);
  assert.equal(inventory.summary.lockfiles, 2);
  assert.equal(inventory.assets[0].evidenceType, 'repository');
  assert.equal(inventory.assets[0].packages.length, 6);
  assert.equal(inventory.assets[0].unresolvedPackages.length, 2);
  assert.ok(!JSON.stringify(inventory).includes(example));
  assert.ok(!JSON.stringify(inventory).includes('https://example.invalid/'));
  for (const source of inventory.sourceFiles) assert.equal(source.sha256, createHash('sha256').update(fs.readFileSync(path.join(example, source.path))).digest('hex'));
});
test('discovery skips symbolic links, hidden trees and dependency/data directories', t => {
  const dir = temporary(t);
  fs.copyFileSync(path.join(example, 'composer.lock'), path.join(dir, 'composer.lock'));
  for (const name of ['node_modules', 'vendor', 'data', '.private']) {
    fs.mkdirSync(path.join(dir, name)); fs.writeFileSync(path.join(dir, name, 'package-lock.json'), 'invalid JSON');
  }
  fs.symlinkSync(example, path.join(dir, 'external'), 'dir');
  fs.mkdirSync(path.join(dir, 'module'));
  fs.copyFileSync(path.join(example, 'package-lock.json'), path.join(dir, 'module', 'package-lock.json'));
  const inventory = collectRepository({ root: dir, id: 'demo', project: 'Demo' });
  assert.equal(inventory.summary.lockfiles, 2);
  assert.equal(inventory.assets.length, 2);
  assert.equal(new Set(inventory.assets.map(a => a.id)).size, 2);
});
test('CLI requires explicit scope and refuses to overwrite output', t => {
  const dir = temporary(t), output = path.join(dir, 'inventory.json');
  assert.throws(() => main([]), /output/);
  main(['--root', example, '--id', 'demo', '--project', 'Demo', '--output', output]);
  const before = fs.readFileSync(output);
  assert.throws(() => main(['--root', example, '--id', 'demo', '--project', 'Demo', '--output', output]), /EEXIST/);
  assert.deepEqual(fs.readFileSync(output), before);
});
