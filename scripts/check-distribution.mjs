import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const workflow = JSON.parse(fs.readFileSync(new URL('../workflows/ciberia.json', import.meta.url)));
assert.equal(workflow.active, false, 'O export publico precisa estar inativo.');
assert.deepEqual(workflow.pinData, {});
assert.ok(!workflow.staticData, 'O export publico nao deve conter estado.');
assert.ok(!workflow.meta, 'O export publico nao deve conter metadados de instancia.');
assert.deepEqual(workflow.tags, []);
for (const node of workflow.nodes) assert.ok(!Object.hasOwn(node, 'credentials'), 'Referencia de credencial no node: ' + node.name);
for (const type of ['n8n-nodes-base.gmail', '@n8n/n8n-nodes-langchain.googleGemini']) {
  assert.equal(workflow.nodes.find(node => node.type === type)?.disabled, true, 'Integracao publica precisa vir desabilitada: ' + type);
}
assert.equal(workflow.settings.saveDataErrorExecution, 'none');
assert.equal(workflow.settings.saveDataSuccessExecution, 'none');
assert.equal(workflow.settings.saveManualExecutions, false);
const code = workflow.nodes.find(node => node.name === 'Configuracao')?.parameters.jsCode;
assert.equal(typeof code, 'string');
const frame = new vm.Script('(function(){' + code + '\n})()').runInNewContext({ $execution: { mode: 'test' } }, { timeout: 2500 })[0].json;
assert.equal(frame.config.dryRun, true);
assert.equal(frame.config.demoOnManual, true);
assert.equal(frame.config.useAI, false);
assert.equal(frame.config.recipient, 'demo@example.invalid');
assert.equal(frame.assets.length, 0);
assert.equal(frame.demo, true);
assert.equal(frame.dryRun, true);
console.log('Export publico: inativo, demonstracao offline, inventario vazio, sem credenciais e sem retencao de execucoes.');
