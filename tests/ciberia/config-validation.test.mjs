import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { configuration } from '../../scripts/ciberia-configuration.mjs';

const workflow = JSON.parse(fs.readFileSync(new URL('../../workflows/ciberia.json', import.meta.url)));
const code = workflow.nodes.find(n => n.name === 'Configuracao').parameters.jsCode;
const marker = '\nreturn (function configuration()';
const at = code.indexOf(marker);
assert.ok(at > 0);
const asset = version => ({
  enabled: true, id: 'demo-asset', project: 'demo-asset', environment: 'teste-isolado',
  packages: [{ ecosystem: 'npm', name: '@demo/component', ...(version === undefined ? {} : { version }), dev: false }],
});
function run(version, { mode = 'test', dryRun = true, recipient = 'security@example.invalid' } = {}) {
  const override = '\nCONFIG.assets=' + JSON.stringify([asset(version)])
    + ';CONFIG.demoOnManual=false;CONFIG.dryRun=' + JSON.stringify(dryRun) + ';CONFIG.recipient=' + JSON.stringify(recipient) + ';\n';
  return new vm.Script('(function(){' + code.slice(0, at) + override + code.slice(at) + '})()')
    .runInNewContext({ $execution: { mode } }, { timeout: 10000 })[0].json;
}

test('the synthetic package version and exact release labels remain unchanged', () => {
  for (const version of ['4.9.5', '4.57.1', '4.60.2', 'v1.2.3', '2.0', '1', '1.0.0-beta.1', '1.0.0+build.1']) {
    assert.equal(run(version).assets[0].packages[0].version, version);
  }
});

test('constraints, branches and URLs fail closed instead of being skipped or normalized', () => {
  for (const version of ['^4.9.5', '~4.9.5', '>=4.9.5', '=4.9.5', '4.*', '4.9.5||5.0.0', 'dev-main', 'workspace:4.9.5', 'file:../pkg', 'git+https://example.invalid/repo', 'http://example.invalid', 'https://example.invalid']) {
    assert.throws(() => run(version), error => {
      assert.match(error.message, /VERSAO_INSTALADA_INVALIDA: demo-asset\/@demo\/component/);
      assert.ok(error.message.includes('versao=' + JSON.stringify(version)));
      assert.ok(error.message.includes('tipo=string'));
      assert.ok(error.message.includes('motivo='));
      return true;
    });
  }
});

test('whitespace including invisible characters is rejected with its code point', () => {
  for (const character of [' ', '\t', '\r', '\n', '\u00A0', '\uFEFF']) {
    assert.throws(() => run('4.9.5' + character), error => {
      assert.ok(error.message.includes('versao=' + JSON.stringify('4.9.5' + character)));
      assert.ok(error.message.includes('espaco em branco U+' + character.codePointAt(0).toString(16).toUpperCase()));
      return true;
    });
  }
});

test('missing, empty and incorrectly typed versions include the received value and type', () => {
  for (const version of [undefined, null, '', 4.95, true, {}, []]) {
    assert.throws(() => run(version), error => {
      assert.ok(error.message.includes('versao=' + JSON.stringify(version)));
      assert.ok(error.message.includes('tipo=' + typeof version));
      return true;
    });
  }
});

test('recipient still rejects CR/LF after regex removal', () => {
  for (const recipient of ['', null, 'security@example.invalid\rBcc:other@example.invalid', 'security@example.invalid\n']) {
    assert.throws(() => run('4.9.5', { recipient }), /destinatario valido/);
  }
});

test('manual and unknown execution modes still cannot send, even when dryRun is false', () => {
  for (const mode of ['test', 'unknown']) {
    assert.equal(run('4.9.5', { mode, dryRun: false }).dryRun, true);
  }
  assert.equal(run('4.9.5', { mode: 'production', dryRun: false }).dryRun, false);
});

test('generators share a self-contained validation function without regex', () => {
  assert.ok(code.includes(configuration.toString()));
  assert.ok(!configuration.toString().includes('.test('));
  assert.ok(!configuration.toString().includes('RegExp'));
  assert.ok(fs.readFileSync(new URL('../../scripts/build-ciberia-v2.mjs', import.meta.url), 'utf8').includes("import { configuration } from './ciberia-configuration.mjs'"));
});
