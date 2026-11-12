import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { buildOfflinePlan } from './ciberia-offline-plan.mjs';

const sha256 = raw => createHash('sha256').update(raw).digest('hex');
const MAX_BYTES = 100 * 1024 * 1024;
function readBytes(file) {
  if (fs.statSync(file).size > MAX_BYTES) throw new Error('Arquivo acima de 100 MiB.');
  return fs.readFileSync(file);
}

export function verifyLockfiles(inventory, root) {
  const base = fs.realpathSync(root);
  if (!Array.isArray(inventory.sourceFiles)) throw new Error('Inventario sem sourceFiles.');
  return inventory.sourceFiles.map(source => {
    if (typeof source.path !== 'string' || path.isAbsolute(source.path) || !['composer.lock', 'package-lock.json'].includes(path.basename(source.path))) throw new Error('Caminho de lockfile invalido.');
    const file = fs.realpathSync(path.resolve(base, source.path));
    if (!file.startsWith(base + path.sep)) throw new Error('Lockfile fora de root.');
    const current = sha256(readBytes(file));
    if (current !== source.sha256) throw new Error('Lockfile mudou desde o inventario: ' + source.path);
    return { path: source.path, sha256: current, unchangedSinceInventory: true };
  });
}

export function buildReport({ input, inventory, root }) {
  if (!input) throw new Error('Informe --input; consulte --help.');
  if (Boolean(inventory) !== Boolean(root)) throw new Error('--inventory e --root devem ser usados juntos.');
  const raw = readBytes(input), parsed = JSON.parse(raw);
  const frame = Array.isArray(parsed) && parsed.length === 1 ? parsed[0]?.json : parsed;
  const plan = buildOfflinePlan(frame);
  const lockfiles = inventory ? verifyLockfiles(JSON.parse(readBytes(inventory)), root) : [];
  plan.provenance = { source: path.basename(input), bytes: raw.length, sha256: sha256(raw), lockfiles, sourceUnmodified: true };
  plan.executionPolicy = { changesAppliedToRepositories: false, dependenciesInstalled: false, externalRequests: 0, emailsSent: 0, merges: 0, deploys: 0 };
  if (sha256(readBytes(input)) !== plan.provenance.sha256) throw new Error('Input mudou durante a analise.');
  return plan;
}

const cell = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('|', '\\|').replace(/[\r\n]/g, ' ').replaceAll('`', '');
export function renderMarkdown(plan) {
  const lines = [
    '# CIBERIA — plano offline', '',
    'Analise de dados exportados. Nao comprova explorabilidade, disponibilidade de releases, compatibilidade ou deploy.', '',
    `Snapshot: ${cell(plan.sourceExecutionAt)}. Ativos: ${plan.scope.assets}. Tarefas de pacotes: ${plan.components.length}.`, '',
    '| Ativo | Ecossistema | Pacote | Versoes observadas | Candidatos na mesma major |',
    '| --- | --- | --- | --- | --- |',
    ...plan.components.map(c => `| ${cell(c.assetId)} | ${cell(c.ecosystem)} | ${cell(c.package)} | ${cell(c.installedVersions.join(', '))} | ${cell(c.targets.map(t => t.candidate || 'revisao manual').join(', '))} |`), '',
    `Ocorrencias PHP pendentes: ${plan.phpPending.length}. Problemas de dados: ${plan.dataIssues.length}. Falhas de fontes: ${plan.sourceFailures.length}.`, '',
    'Os candidatos sao fronteiras numericas dos advisories presentes no snapshot. Resolva dependencias em ambiente isolado, revise o lockfile, execute os testes da aplicacao e renove a evidencia apos o deploy autorizado.', '',
    'Hashes SHA-256 do input e dos lockfiles opcionais ficam no JSON. O conteudo dos inputs foi tratado como dados; nao houve rede, email, instalacao ou execucao de codigo do export.', '',
  ];
  return lines.join('\n');
}

export function main(argv = process.argv.slice(2)) {
  if (argv.includes('--help')) {
    console.log('Uso: node scripts/build-ciberia-offline-report.mjs --input <frame.json> --output-dir <diretorio-novo> [--inventory <inventario.json> --root <repositorio>]\nInput: frame JSON ou um item n8n [{"json": frame}] exportado do node Avaliar evidencias. A verificacao opcional compara hashes dos lockfiles, sem executar codigo do input.');
    return;
  }
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--input', '--output-dir', '--inventory', '--root'].includes(argv[i]) || !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error('Argumento invalido; consulte --help.');
    options[argv[i].slice(2)] = argv[i + 1];
  }
  if (!options['output-dir']) throw new Error('Informe --output-dir; consulte --help.');
  const plan = buildReport(options), destination = path.resolve(options['output-dir']);
  fs.mkdirSync(destination, { recursive: true });
  const files = { json: path.join(destination, 'plan.json'), markdown: path.join(destination, 'plan.md') };
  if (Object.values(files).some(file => fs.existsSync(file))) throw new Error('Saida ja existe; use outro diretorio.');
  fs.writeFileSync(files.json, JSON.stringify(plan, null, 2) + '\n', { flag: 'wx' });
  fs.writeFileSync(files.markdown, renderMarkdown(plan), { flag: 'wx' });
  console.log(JSON.stringify({ tasks: plan.components.length, dataIssues: plan.dataIssues.length, files }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error('CIBERIA: ' + error.message); process.exitCode = 1; }
}
