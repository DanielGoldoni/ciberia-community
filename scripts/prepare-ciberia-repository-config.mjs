import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const MAX_BYTES = 100 * 1024 * 1024;
const ignored = new Set(['node_modules', 'vendor', '.git', 'storage', 'public', 'data']);
const sha256 = raw => createHash('sha256').update(raw).digest('hex');

export function isVersion(value) {
  return typeof value === 'string' && /^v?\d+(?:\.\d+){0,3}(?:[-+_.][A-Za-z0-9._-]+)?$/.test(value);
}
const unresolved = (ecosystem, name, dev) => ({ ecosystem, name, dev, reason: 'Sem versao exata numerica; referencia/URL omitida e pacote nao consultado.' });

export function composerPackages(lock) {
  const packages = [], skipped = [];
  for (const [field, dev] of [['packages', false], ['packages-dev', true]]) {
    if (lock[field] !== undefined && !Array.isArray(lock[field])) throw new Error('Lista Composer invalida: ' + field);
    for (const entry of lock[field] || []) {
      if (typeof entry?.name !== 'string' || !entry.name.includes('/')) throw new Error('Nome Composer invalido.');
      if (!isVersion(entry.version)) skipped.push(unresolved('Packagist', entry.name, dev));
      else packages.push({ ecosystem: 'Packagist', name: entry.name, version: entry.version, dev });
    }
  }
  return { packages, unresolved: skipped };
}

export function npmPackages(lock) {
  if (!lock.packages || typeof lock.packages !== 'object' || Array.isArray(lock.packages) || ![2, 3].includes(lock.lockfileVersion)) throw new Error('Coletor espera package-lock v2/v3.');
  const packages = [], skipped = [];
  for (const [location, entry] of Object.entries(lock.packages)) {
    if (!location) continue;
    if (!entry || typeof entry !== 'object') throw new Error('Entrada npm invalida.');
    let name = entry.name || location.split('node_modules/').pop();
    if (!entry.name && typeof entry.resolved === 'string') {
      try {
        const url = new URL(entry.resolved);
        if (url.hostname === 'registry.npmjs.org' && url.pathname.includes('/-/')) name = decodeURIComponent(url.pathname.slice(1).split('/-/')[0]);
      } catch { /* URLs are inspected only to resolve aliases, never exported. */ }
    }
    const dev = entry.dev === true;
    if (typeof name !== 'string' || !name || entry.link || !isVersion(entry.version)) skipped.push(unresolved('npm', typeof name === 'string' ? name : '(sem nome)', dev));
    else packages.push({ ecosystem: 'npm', name, version: entry.version, dev, ...(entry.optional ? { optional: true } : {}), ...(entry.devOptional ? { devOptional: true } : {}) });
  }
  return { packages, unresolved: skipped };
}

export function deduplicate(packages) {
  const map = new Map();
  for (const pkg of packages) {
    const key = JSON.stringify([pkg.ecosystem, pkg.name, pkg.version]);
    const before = map.get(key);
    if (!before) map.set(key, { ...pkg });
    else {
      before.dev = before.dev && pkg.dev;
      if (!pkg.optional) delete before.optional;
      if (!pkg.devOptional) delete before.devOptional;
    }
  }
  return [...map.values()].sort((a, b) => a.ecosystem.localeCompare(b.ecosystem) || a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

export function collectRepository({ root, id, project, observedAt = new Date().toISOString(), maxDepth = 5 }) {
  if (!root || !id || !project) throw new Error('Informe root, id e project.');
  const base = fs.realpathSync(root);
  if (!fs.statSync(base).isDirectory()) throw new Error('root precisa ser um diretorio.');
  const locks = [];
  function visit(dir, depth) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isFile() && ['composer.lock', 'package-lock.json'].includes(entry.name)) {
        locks.push(full);
        if (locks.length > 1000) throw new Error('Limite de 1000 lockfiles excedido.');
      } else if (entry.isDirectory() && depth < maxDepth && !ignored.has(entry.name) && !entry.name.startsWith('.')) visit(full, depth + 1);
    }
  }
  visit(base, 0);
  if (!locks.length) throw new Error('Nenhum composer.lock/package-lock.json encontrado no root informado.');
  const groups = new Map(), sourceFiles = [];
  for (const file of locks) {
    if (fs.statSync(file).size > MAX_BYTES) throw new Error('Lockfile acima de 100 MiB.');
    const raw = fs.readFileSync(file), lock = JSON.parse(raw);
    const result = path.basename(file) === 'composer.lock' ? composerPackages(lock) : npmPackages(lock);
    const module = path.relative(base, path.dirname(file)).split(path.sep).join('/') || '.';
    if (!groups.has(module)) groups.set(module, { packages: [], unresolved: [], lockfiles: [] });
    const group = groups.get(module);
    const record = { path: path.relative(base, file).split(path.sep).join('/'), sha256: sha256(raw) };
    group.packages.push(...result.packages); group.unresolved.push(...result.unresolved); group.lockfiles.push(record); sourceFiles.push(record);
  }
  const assets = [...groups.entries()].map(([module, group]) => ({
    enabled: true, id: module === '.' ? id : id + '--' + encodeURIComponent(module),
    project: module === '.' ? project : project + ' / ' + module,
    environment: 'repository-snapshot', evidenceType: 'repository', observedAt,
    evidence: 'Lockfiles locais; nao comprovam instalacao, runtime ou deploy.',
    repository: { module }, lockfiles: group.lockfiles,
    unresolvedPackages: group.unresolved, packages: deduplicate(group.packages),
  }));
  return {
    summary: { collectedAt: observedAt, assets: assets.length, lockfiles: sourceFiles.length, packageOccurrences: assets.reduce((n, a) => n + a.packages.length, 0), externalRequests: 0 },
    boundary: 'Apenas o root informado foi lido. Nao coleta Git, .env, credenciais, dados n8n ou versoes PHP inferidas. Os nomes/caminhos do inventario ainda podem ser privados: nao publique o resultado automaticamente.',
    assets, sourceFiles,
  };
}

export function main(argv = process.argv.slice(2)) {
  if (argv.includes('--help')) {
    console.log('Uso: node scripts/prepare-ciberia-repository-config.mjs --root <diretorio> --id <id> --project <nome> --output <inventario.json>\nLe composer.lock e package-lock v2/v3 ate 5 niveis, sem rede ou execucao de scripts. Saida nova, sem sobrescrever arquivos.');
    return;
  }
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--root', '--id', '--project', '--output'].includes(argv[i]) || !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error('Argumento invalido; consulte --help.');
    options[argv[i].slice(2)] = argv[i + 1];
  }
  if (!options.output) throw new Error('Informe --output; consulte --help.');
  const inventory = collectRepository(options);
  fs.mkdirSync(path.dirname(path.resolve(options.output)), { recursive: true });
  fs.writeFileSync(options.output, JSON.stringify(inventory, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ ...inventory.summary, output: options.output }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error('CIBERIA: ' + error.message); process.exitCode = 1; }
}
