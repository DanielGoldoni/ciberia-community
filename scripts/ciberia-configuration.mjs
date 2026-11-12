// Serialized into the n8n Code node by the generators. Keep self-contained:
// CONFIG and $execution are supplied by n8n, not by this module.
export function configuration() {
  // Public n8n metadata uses 'test' / 'production', not the internal 'manual' enum.
  // Fail closed: any unknown/non-production execution is preview-only.
  const manual = $execution.mode !== 'production';
  const demo = manual && CONFIG.demoOnManual === true;
  const issues = [];
  function versionProblem(version) {
    if (typeof version !== 'string') return 'a versao deve ser uma string';
    if (!version.length) return 'versao vazia';
    // No regex/escaping dependency in copied or exported Code nodes.
    for (const character of version) {
      if (!character.trim()) return 'espaco em branco U+' + character.codePointAt(0).toString(16).toUpperCase();
      if ('<>=~^*|'.includes(character)) return 'operador de constraint ' + character;
    }
    const prefix = ['dev-', 'workspace:', 'file:', 'git+', 'http:', 'https:'].find(value => version.startsWith(value));
    if (prefix) return 'branch/URL/referencia ' + prefix;
    return '';
  }
  if (!Array.isArray(CONFIG.assets)) throw new Error('CONFIG.assets precisa ser um array.');
  if (!Number.isFinite(CONFIG.maxInventoryAgeHours) || CONFIG.maxInventoryAgeHours <= 0) throw new Error('Idade de inventario invalida.');
  if (!Number.isFinite(CONFIG.reminderHours) || CONFIG.reminderHours < 1) throw new Error('Intervalo de lembrete invalido.');
  if (!Number.isInteger(CONFIG.maxAlertsPerEmail) || CONFIG.maxAlertsPerEmail < 1 || CONFIG.maxAlertsPerEmail > 250) throw new Error('maxAlertsPerEmail deve estar entre 1 e 250.');
  const assets = CONFIG.assets.filter(a => a.enabled !== false);
  const ids = new Set();
  for (const asset of assets) {
    if (!asset.id || !asset.project || !asset.environment) throw new Error('Cada ativo precisa de id, project e environment.');
    if (ids.has(asset.id)) throw new Error('asset.id duplicado: ' + asset.id);
    ids.add(asset.id);
    if (!Array.isArray(asset.packages)) throw new Error('packages precisa ser um array: ' + asset.id);
    for (const p of asset.packages) {
      if (!p || !['Packagist', 'npm'].includes(p.ecosystem) || typeof p.name !== 'string' || !p.name.trim()) {
        throw new Error('Pacote invalido em ' + asset.id + ': use Packagist/npm, name e version exata.');
      }
      const problem = versionProblem(p.version);
      if (problem) {
        throw new Error('VERSAO_INSTALADA_INVALIDA: ' + asset.id + '/' + p.name
          + ' | versao=' + JSON.stringify(p.version) + ' | tipo=' + typeof p.version
          + ' | motivo=' + problem + '. Informe a versao exata do lockfile/runtime, nao uma constraint.');
      }
    }
  }
  if (!demo && !assets.length) issues.push('Inventario vazio: nenhum ativo real esta habilitado. A cobertura ainda nao foi configurada.');
  if (!demo && (typeof CONFIG.recipient !== 'string' || !CONFIG.recipient
    || CONFIG.recipient.includes(String.fromCharCode(13)) || CONFIG.recipient.includes(String.fromCharCode(10)))) {
    throw new Error('Configure recipient com um destinatario valido.');
  }
  return [{ json: {
    config: { ...CONFIG, assets: undefined }, assets,
    demo, manual, dryRun: demo || manual || CONFIG.dryRun !== false,
    issues, generatedAt: new Date().toISOString(),
    note: 'Manual sempre sem email e sem gravacao de estado. demoOnManual=false consulta fontes reais em modo de previa.',
  } }];
}
