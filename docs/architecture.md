# Arquitetura

## Mapa de código

| Arquivo | Responsabilidade |
| --- | --- |
| `scripts/build-ciberia-v2.mjs` | `buildWorkflow()`: nós, conexões, configuração, consultas, análise, deduplicação e HTML |
| `scripts/ciberia-configuration.mjs` | Função compartilhada serializada no Code node; valida versões e protege execuções manuais |
| `workflows/ciberia.json` | Distribuição reproduzível para importar no n8n |
| `scripts/prepare-ciberia-repository-config.mjs` | Coletor explícito de lockfiles, versões e hashes |
| `scripts/ciberia-offline-plan.mjs` | Análise pura de faixas, múltiplas versões e candidatos do snapshot |
| `scripts/build-ciberia-offline-report.mjs` | CLI JSON/Markdown, hash do input e verificação opcional de lockfiles |
| `scripts/check-distribution.mjs` | Verifica a configuração segura do export público |
| `tests/ciberia/` | Testes dos Code nodes, expressões, grafo e configuração |
| `tests/*.test.mjs` | Testes do coletor, plano e relatório offline |

## Como funciona

O builder transforma funções JavaScript em Code nodes autocontidos. Os identificadores são derivados dos nomes dos nós; o `versionId` deriva do conteúdo. O workflow resultante não depende de caminhos ou arquivos da máquina que o gerou. O builder, por sua vez, lê a fixture sintética versionada junto dos testes.

A configuração decide entre demonstração offline e consultas de fontes. Na demonstração, o inventário e os advisories são fictícios; a rota não passa pelos nós HTTP nem pelas integrações. Fora dela, as consultas OSV são deduplicadas por ecossistema, pacote e versão, preservando a associação de cada versão aos ativos.

OSV faz o matching online de npm/Packagist. O workflow normaliza resultados, busca detalhes e registra falhas de cobertura. Fontes que compartilham uma CVE são consolidadas preservando a maior severidade e a união dos aliases, fontes e limites de correção, sem depender da ordem de chegada. PHP usa advisories estruturados de `php/php-src`, faixas numéricas simples, evidência de distribuição/extensões e comunicados condicionais do php.net. A análise produz estados como `DEPENDENCIA_NO_REPOSITORIO`, `AFETADO_POR_VERSAO`, `POTENCIAL_REQUER_ANALISE`, `BOLETIM_REQUER_ANALISE` e `COBERTURA_INCOMPLETA`.

O relatório determinístico precede a IA opcional. A deduplicação compara fingerprints e intervalo de lembrete, limita o lote por email e mantém excedentes elegíveis. A rota de envio exige execução de produção, `dryRun: false` e novidades. O registro de envio só avança após resposta com ID do Gmail. O estado não possui transações nem exclusão mútua.

O plano offline lê a saída completa da análise, reconstrói as ocorrências por versão e agrupa altas/críticas por ativo e pacote. Um candidato precisa sair de todas as faixas altas/críticas comparáveis daquele pacote presentes no snapshot. Versões/faixas não suportadas exigem revisão; não há resolução pelo Composer/npm nem consulta de disponibilidade de releases.

Os testes executam os Code nodes com contexto n8n simulado e timeout via `node:vm`. Esse uso testa funções conhecidas do repositório; não transforma `vm` em sandbox para código arbitrário. Os relatórios fornecidos pelo operador são processados exclusivamente como JSON.

## Fronteiras

O coletor conhece apenas lockfiles sob o diretório informado. O workflow conhece apenas o inventário configurado e as fontes consultadas. Nenhuma dessas etapas comprova deploy, exposição ou exploração. Não existe caminho automático de correção, instalação ou publicação de mudanças em aplicações analisadas.
