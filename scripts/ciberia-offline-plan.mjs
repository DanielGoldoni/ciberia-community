// Pure analysis of an exported n8n JSON. Never evaluates code, accesses the
// network, installs dependencies or executes instructions found in the export.
export const normalizeSeverity = value => {
  const text = String(value || '').toLowerCase();
  if (text === 'moderate') return 'medium';
  return ['critical', 'high', 'medium', 'low'].includes(text) ? text : 'unknown';
};
export const isHigh = value => ['critical', 'high'].includes(normalizeSeverity(value));
export function numericVersion(value) {
  if (value === '0') return [0, 0, 0];
  const match = String(value).match(/^v?(\d+)\.(\d+)\.(\d+)$/);
  const numbers = match?.slice(1).map(Number);
  return numbers?.every(Number.isSafeInteger) ? numbers : null;
}
function releaseVersion(value) {
  if (value === '0') return { numbers: [0, 0, 0], prerelease: [] };
  const m = String(value).match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!m) return null;
  const numbers = m.slice(1, 4).map(Number), prerelease = m[4] ? m[4].split('.') : [];
  if (!numbers.every(Number.isSafeInteger) || prerelease.some(p => /^\d+$/.test(p) && !Number.isSafeInteger(Number(p)))) return null;
  return { numbers, prerelease };
}
export function compareVersions(a, b) {
  const av = releaseVersion(a), bv = releaseVersion(b);
  if (!av || !bv) return null;
  for (let i = 0; i < 3; i++) if (av.numbers[i] !== bv.numbers[i]) return av.numbers[i] - bv.numbers[i];
  if (!av.prerelease.length || !bv.prerelease.length) return Number(!av.prerelease.length) - Number(!bv.prerelease.length);
  for (let i = 0; i < Math.max(av.prerelease.length, bv.prerelease.length); i++) {
    const x = av.prerelease[i], y = bv.prerelease[i];
    if (x === undefined || y === undefined) return Number(x !== undefined) - Number(y !== undefined);
    if (x === y) continue;
    const xn = /^\d+$/.test(x), yn = /^\d+$/.test(y);
    if (xn && yn) return Number(x) - Number(y);
    if (xn !== yn) return xn ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}
export function rangeContains(range, candidate) {
  if (!releaseVersion(candidate) || !['SEMVER', 'ECOSYSTEM'].includes(range.type) || !Array.isArray(range.events) || !range.events.length) return null;
  let start = null, uncertain = false;
  for (const event of range.events || []) {
    if (event.introduced !== undefined) {
      start = event.introduced;
      if (!releaseVersion(start)) uncertain = true;
    } else {
      const end = event.fixed ?? event.last_affected ?? event.limit;
      if (end === undefined) { uncertain = true; continue; }
      if (start === null || !releaseVersion(start) || !releaseVersion(end)) { uncertain = true; start = null; continue; }
      const lower = compareVersions(candidate, start), upper = compareVersions(candidate, end);
      if (lower >= 0 && (event.last_affected !== undefined ? upper <= 0 : upper < 0)) return true;
      start = null;
    }
  }
  if (start !== null && releaseVersion(start) && compareVersions(candidate, start) >= 0) return true;
  return uncertain ? null : false;
}
export function packageAffected(detail, ecosystem, name, candidate) {
  if (detail.withdrawn) return false;
  if (!releaseVersion(candidate)) return null;
  const rows = (detail.affected || []).filter(a => a.package?.name === name && a.package?.ecosystem === ecosystem);
  if (!rows.length) return null;
  let uncertain = false;
  for (const row of rows) {
    if ((row.versions || []).some(v => compareVersions(v, candidate) === 0)) return true;
    const ranges = row.ranges || [];
    if (!ranges.length && !(row.versions || []).length) uncertain = true;
    for (const range of ranges) {
      const result = rangeContains(range, candidate);
      if (result === true) return true;
      if (result === null) uncertain = true;
    }
  }
  return uncertain ? null : false;
}
export function severityOf(detail, ecosystem, name) {
  const rows = (detail.affected || []).filter(a => a.package?.name === name && a.package?.ecosystem === ecosystem);
  const values = [detail.database_specific?.severity, ...rows.flatMap(r => [r.database_specific?.severity, r.ecosystem_specific?.severity])].map(normalizeSeverity);
  return ['critical', 'high', 'medium', 'low'].find(s => values.includes(s)) || 'unknown';
}
const idOf = detail => (detail.aliases || []).filter(x => /^CVE-\d{4}-\d+$/.test(x)).sort()[0] || detail.id;
const uniqueSorted = values => [...new Map(values.map(value => [JSON.stringify(value), value])).entries()]
  .sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value);
const severityRank = value => ['critical', 'high', 'medium', 'low', 'unknown'].indexOf(normalizeSeverity(value));
function mergeAdvisoryRecords(a, b) {
  // The highest-severity source supplies display metadata; ID breaks ties.
  // All other evidence survives even when several OSV records share one CVE.
  const first = severityRank(a.severity) - severityRank(b.severity) || a.osvId.localeCompare(b.osvId);
  const primary = first <= 0 ? a : b;
  return {
    ...primary,
    osvIds: uniqueSorted([...a.osvIds, ...b.osvIds]),
    aliases: uniqueSorted([...a.aliases, ...b.aliases]),
    cwe: uniqueSorted([...a.cwe, ...b.cwe]),
    cvssVectorsFromSource: uniqueSorted([...a.cvssVectorsFromSource, ...b.cvssVectorsFromSource]),
    fixed: uniqueSorted([...a.fixed, ...b.fixed]),
    sources: uniqueSorted([...a.sources, ...b.sources]),
    advisoryEvidence: uniqueSorted([...a.advisoryEvidence, ...b.advisoryEvidence]),
    rangeCheckForInstalled: a.rangeCheckForInstalled === true || b.rangeCheckForInstalled === true ? true : null,
  };
}
export function packageDetails(details, ecosystem, name) {
  return details.filter(d => !d.withdrawn && (d.affected || []).some(a => a.package?.name === name && a.package?.ecosystem === ecosystem));
}
export function fixedBoundaries(details, ecosystem, name) {
  return [...new Set(details.flatMap(d => (d.affected || []).filter(a => a.package?.name === name && a.package?.ecosystem === ecosystem)
    .flatMap(a => (a.ranges || []).flatMap(r => (r.events || []).flatMap(e => e.fixed ? [e.fixed] : [])))))];
}
export function chooseCandidates(installedVersions, details, ecosystem, name, extraCandidates = []) {
  const relevant = packageDetails(details, ecosystem, name);
  const hc = relevant.filter(d => isHigh(severityOf(d, ecosystem, name)));
  const boundaries = [...new Set([...fixedBoundaries(relevant, ecosystem, name), ...extraCandidates])].filter(numericVersion).sort(compareVersions);
  const majors = [...new Set(installedVersions.map(numericVersion).filter(Boolean).map(v => v[0]))];
  return majors.map(major => {
    const installed = installedVersions.filter(v => numericVersion(v)?.[0] === major).sort(compareVersions).at(-1);
    const checks = boundaries.filter(v => numericVersion(v)[0] === major && compareVersions(v, installed) > 0).map(version => ({
      version,
      remaining: uniqueSorted(hc.filter(d => packageAffected(d, ecosystem, name, version) === true).map(idOf)),
      uncertain: uniqueSorted(hc.filter(d => packageAffected(d, ecosystem, name, version) === null).map(idOf)),
    }));
    const candidate = checks.find(c => !c.remaining.length && !c.uncertain.length);
    const alternatives = boundaries.filter(v => numericVersion(v)[0] !== major && compareVersions(v, installed) > 0)
      .filter(v => hc.every(d => packageAffected(d, ecosystem, name, v) === false));
    return {
      installedMajor: major,
      candidate: candidate?.version || null,
      assessment: candidate ? 'Fora das faixas altas/criticas dos advisories deste pacote presentes no snapshot; compatibilidade e disponibilidade ainda precisam ser verificadas.' : 'Sem candidato numerico na mesma major que elimine todas as altas/criticas conhecidas neste snapshot.',
      upgradeAlternatives: alternatives.slice(0, 5),
      rejectedCandidates: checks.filter(c => c.remaining.length || c.uncertain.length),
    };
  });
}

export function buildOfflinePlan(frame) {
  if (!frame || !Array.isArray(frame.assets) || !Array.isArray(frame.findings) || !Array.isArray(frame.details) || !Array.isArray(frame.osvMatches)) throw new Error('Export sem inventario/findings/detalhes/matches completos.');
  const detailById = new Map(frame.details.map(d => [d.id, d]));
  const assets = new Map(frame.assets.map(a => [a.id, a]));
  const packageFindings = new Map();
  const dataIssues = [];
  for (const match of frame.osvMatches) {
    const detail = detailById.get(match.id);
    if (!detail) { dataIssues.push({ id: match.id, reason: 'Detalhe ausente' }); continue; }
    if (detail.withdrawn) continue;
    for (const target of match.targets || []) {
      const pkg = target.package;
      const asset = assets.get(target.assetId);
      if (!asset || !pkg || !asset.packages.some(p => p.ecosystem === pkg.ecosystem && p.name === pkg.name && p.version === pkg.version)) {
        dataIssues.push({ id: match.id, assetId: target.assetId, reason: 'Target nao pertence ao inventario do ativo' }); continue;
      }
      const rows = (detail.affected || []).filter(a => a.package?.name === pkg.name && a.package?.ecosystem === pkg.ecosystem);
      if (!rows.length) { dataIssues.push({ id: match.id, reason: 'Detalhe nao contem o pacote/ecossistema' }); continue; }
      const installedCheck = packageAffected(detail, pkg.ecosystem, pkg.name, pkg.version);
      if (installedCheck === false) {
        dataIssues.push({ id: match.id, assetId: target.assetId, reason: 'A versao instalada esta fora das faixas do detalhe fornecido' });
        continue;
      }
      const canonical = idOf(detail);
      const key = JSON.stringify([target.assetId, pkg.ecosystem, pkg.name, pkg.version, canonical]);
      const severity = severityOf(detail, pkg.ecosystem, pkg.name);
      const finding = {
        assetId: target.assetId, ecosystem: pkg.ecosystem, package: pkg.name, installed: pkg.version,
        dev: pkg.dev === true, optional: pkg.optional === true, devOptional: pkg.devOptional === true,
        id: canonical, osvId: detail.id, osvIds: [detail.id], aliases: uniqueSorted(detail.aliases || []), title: detail.summary || canonical,
        severity, status: 'DEPENDENCIA_NO_REPOSITORIO',
        cwe: uniqueSorted(detail.database_specific?.cwe_ids || []), cvssVectorsFromSource: uniqueSorted(detail.severity || []),
        severityLabelFromSource: detail.database_specific?.severity || null,
        fixed: uniqueSorted(fixedBoundaries([detail], pkg.ecosystem, pkg.name)),
        sources: uniqueSorted([...(detail.references || []).filter(r => r.type === 'ADVISORY').map(r => r.url), ...(!detail.id.startsWith('DEMO-') ? ['https://osv.dev/vulnerability/' + encodeURIComponent(detail.id)] : [])]),
        modified: detail.modified,
        rangeCheckForInstalled: installedCheck,
        advisoryEvidence: [{ osvId: detail.id, severity, severityLabelFromSource: detail.database_specific?.severity || null, modified: detail.modified, rangeCheckForInstalled: installedCheck }],
        condition: 'Versao identificada pelo OSV no inventario de repositorio; alcance no runtime e explorabilidade dependem do codigo/configuracao publicados.',
      };
      const before = packageFindings.get(key);
      packageFindings.set(key, before ? mergeAdvisoryRecords(before, finding) : finding);
    }
  }
  const fullPackageFindings = [...packageFindings.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, finding]) => finding);
  const selected = fullPackageFindings.filter(f => isHigh(f.severity));
  const groups = new Map();
  for (const finding of selected) {
    const key = JSON.stringify([finding.assetId, finding.ecosystem, finding.package]);
    if (!groups.has(key)) groups.set(key, { assetId: finding.assetId, ecosystem: finding.ecosystem, package: finding.package, installedVersions: [], occurrences: [], advisories: [] });
    const group = groups.get(key);
    if (!group.installedVersions.includes(finding.installed)) {
      group.installedVersions.push(finding.installed);
      group.occurrences.push({ version: finding.installed, dev: finding.dev, optional: finding.optional, devOptional: finding.devOptional });
    }
    const advisory = Object.fromEntries(['id', 'osvId', 'osvIds', 'aliases', 'title', 'severity', 'severityLabelFromSource', 'modified', 'cwe', 'cvssVectorsFromSource', 'fixed', 'sources', 'advisoryEvidence', 'rangeCheckForInstalled'].map(key => [key, finding[key]]));
    const index = group.advisories.findIndex(a => a.id === finding.id);
    if (index < 0) group.advisories.push(advisory);
    else group.advisories[index] = mergeAdvisoryRecords(group.advisories[index], advisory);
  }
  const components = [...groups.values()];
  for (const component of components) {
    component.targets = chooseCandidates(component.installedVersions, frame.details, component.ecosystem, component.package);
    component.priority = 'REVIEW_CONTEXT_AND_TEST';
    component.unsupportedInstalledVersions = component.installedVersions.filter(v => !numericVersion(v));
    component.status = component.targets.length && !component.unsupportedInstalledVersions.length && component.targets.every(t => t.candidate) ? 'CANDIDATO_PARA_RESOLVER_E_TESTAR' : 'MIGRACAO_OU_BACKPORT_A_AVALIAR';
    component.compatibilityStatus = 'NAO_RESOLVIDA_PELO_GERENCIADOR';
  }
  components.sort((a, b) => a.assetId.localeCompare(b.assetId) || a.ecosystem.localeCompare(b.ecosystem) || a.package.localeCompare(b.package));
  const monitorHC = frame.findings.filter(f => isHigh(f.severity));
  const phpPending = monitorHC.filter(f => f.ecosystem === 'php');
  const counts = items => items.reduce((result, item) => (result[item.severity] = (result[item.severity] || 0) + 1, result), {});
  const byAsset = frame.assets.map(asset => {
    const records = selected.filter(f => f.assetId === asset.id);
    const tasks = components.filter(c => c.assetId === asset.id);
    return { id: asset.id, project: asset.project, environment: asset.environment, evidenceType: asset.evidenceType, observedAt: asset.observedAt, packageCount: asset.packages.length, monitorPackageHighCritical: monitorHC.filter(f => f.assetId === asset.id && f.ecosystem !== 'php').length, allVersionsHighCritical: records.length, components: tasks.length, phpVersion: asset.php?.version || null, phpHighCriticalPending: phpPending.filter(f => f.assetId === asset.id).length, taskKeys: tasks.map(t => t.ecosystem + ':' + t.package) };
  });
  const monitorKeys = new Set(monitorHC.filter(f => f.ecosystem !== 'php').map(f => JSON.stringify([f.assetId, f.ecosystem, f.package, f.id])));
  const reconstructedKeys = new Set(selected.map(f => JSON.stringify([f.assetId, f.ecosystem, f.package, f.id])));
  for (const key of monitorKeys) if (!reconstructedKeys.has(key)) dataIssues.push({ key, reason: 'Alta/critica do monitor nao reconstruida' });
  return {
    generatedAt: new Date().toISOString(), sourceExecutionAt: frame.generatedAt,
    scope: { assets: frame.assets.length, packageOccurrences: frame.assets.reduce((n, a) => n + a.packages.length, 0), uniqueQueries: frame.queryCount, osvMatches: frame.osvMatches.length, advisoryDetails: frame.details.length, includeDev: frame.config?.includeDev === true, includeTransitive: true, includeOptional: true, analysis: 'OFFLINE_SEM_CONSULTA_EXTERNA', emailBatchLimitApplied: false },
    summary: { originalFindings: frame.findings.length, monitorHighCritical: monitorHC.length, monitorPackageHighCritical: monitorHC.length - phpPending.length, phpHighCriticalPending: phpPending.length, allVersionsPackageHighCritical: selected.length, allVersionsSeverityCounts: counts(selected), packageRemediationTasks: components.length, uniquePackageNames: new Set(components.map(c => c.ecosystem + ':' + c.package)).size, allVersionPackageFindings: fullPackageFindings.length, normalizedSeverityCounts: counts(fullPackageFindings), moderatePreviouslyUnknown: frame.findings.filter(f => f.severity === 'unknown' && (f.aliases || []).some(id => normalizeSeverity(detailById.get(id)?.database_specific?.severity) === 'medium')).length, dataIssues: dataIssues.length },
    boundary: 'Plano para todas as altas/criticas do export fornecido, incluindo versoes multiplas do mesmo pacote. Candidatos avaliados somente contra advisories do snapshot; isso nao comprova disponibilidade, compatibilidade, ausencia de CVEs novas ou deploy. Nao executou codigo do export, instalacoes, rede, email, merge ou deploy.',
    sourceFailures: frame.failures || [], dataIssues, byAsset, components, highCriticalPackageFindings: selected, phpPending,
    unknownSeverityPackageFindings: fullPackageFindings.filter(f => f.severity === 'unknown'),
    informationalBulletins: frame.findings.filter(f => f.status === 'BOLETIM_REQUER_ANALISE').map(f => ({ id: f.id, title: f.title, sources: f.sources, evidence: f.evidence })),
    unresolvedPackages: frame.assets.flatMap(a => (a.unresolvedPackages || []).map(p => ({ assetId: a.id, ...p }))),
  };
}
