# Uso e configuração

## Mapa de código

- `workflows/ciberia.json`: export pronto para importar como novo workflow.
- `scripts/build-ciberia-v2.mjs`: gera os nós, as conexões e a configuração padrão.
- `scripts/ciberia-configuration.mjs`: valida o inventário e protege execução manual.
- `scripts/prepare-ciberia-repository-config.mjs`: coleta lockfiles de um diretório explícito.
- `scripts/build-ciberia-offline-report.mjs`: gera JSON/Markdown da saída de **Avaliar evidencias**.
- `examples/`: entradas fictícias para experimentar sem dados reais.

## Instalação local opcional

O Compose usa n8n **2.47.5**, porta local 5679 e volume próprio. Não monta pastas de outra instalação, não importa credenciais e não ativa o workflow.

```sh
docker compose up -d
```

Abra `http://localhost:5679`, crie o administrador local e importe `workflows/ciberia.json` pelo editor como novo workflow. O diretório `/imports` também fica disponível, somente para leitura, dentro do container. Não publique o workflow nesta etapa. O download da imagem e a instalação local usam rede; a rota de demonstração do workflow é offline.

```sh
docker compose down
```

Esse comando encerra a instalação e preserva o volume. O volume armazena configuração do n8n e possíveis credenciais criadas pelo operador: mantenha-o privado. Este Compose é um ponto de partida local; hospedagem pública requer configuração própria de TLS, autenticação, backups, atualização e operação.

## Três modos de operação

| Modo | Configuração | Rede | Email / IA / deduplicação |
| --- | --- | --- | --- |
| Demonstração padrão | Manual no editor, `demoOnManual: true` | Nenhuma chamada de fonte | Nenhum |
| Prévia com inventário próprio | Manual no editor, `demoOnManual: false` | OSV, GitHub, php.net | Nenhum |
| Monitoramento configurado | Publicado/agendado, `dryRun: false` | Fontes e integrações habilitadas | Gmail; IA opcional; estado após confirmação |

Uma execução manual **pelo editor** permanece em prévia mesmo se `dryRun` for `false`. A CLI `n8n execute` é tratada como produção pelo contexto dos Code nodes; mantenha `dryRun: true` ao usá-la para testes. O fluxo padrão tem `assets: []`, `recipient: "demo@example.invalid"`, `useAI: false` e Gmail/Gemini desabilitados. O destinatário fictício não deve ser usado para envio real.

## Preparar o inventário

```sh
node scripts/prepare-ciberia-repository-config.mjs --root /caminho/do/seu/repositorio --id meu-app --project "Meu App" --output local/inventory.json
```

O coletor lê `composer.lock` e `package-lock.json` v2/v3 até cinco níveis. Ignora links simbólicos, diretórios ocultos, `node_modules`, `vendor`, `storage`, `public` e `data`. Não lê `.env`, não executa o gerenciador de pacotes e não consulta Git ou servidores. Dependências sem versão numérica exata ficam em `unresolvedPackages`. O resultado registra hashes dos lockfiles e caminhos relativos, mas pode conter nomes privados de pacotes, projetos e módulos.

No nó **Configuracao**, copie somente o array `assets` do inventário para `CONFIG.assets`. Cada ativo precisa de `id` único, `project`, `environment`, `observedAt`, `evidenceType`, `evidence` e `packages`. A data representa a coleta; não prova um deploy. O coletor inclui dependências de desenvolvimento, enquanto o workflow usa `includeDev: false` por padrão; escolha essa cobertura explicitamente.

Informe versões exatas como `1.2.3`, não constraints como `^1.2`. Lockfiles permanecem `evidenceType: "repository"`. Para PHP, acrescente a versão **medida no processo web**, distribuição e evidências; não infira runtime pela versão do CLI ou tag genérica de imagem. Use `distribution: "unknown"` se fornecedor/backports não estiverem comprovados.

Mude `demoOnManual` para `false` e execute manualmente para obter a prévia. Essa etapa envia nomes/ecossistemas/versões de pacotes ao OSV; revise [o fluxo de dados](privacy.md) antes de usar inventários privados.

## Notificações e IA opcionais

Antes de publicar/agendar:

1. Preencha um destinatário real autorizado a receber os dados do inventário.
2. No nó **Enviar um unico email**, selecione suas próprias credenciais Gmail e habilite o nó. A credencial fica na instalação n8n, fora deste repositório.
3. Mantenha `useAI: false` para o relatório determinístico. Para usar Gemini, selecione credencial e modelo disponíveis na sua conta, habilite **Explicar com Gemini** e então defina `useAI: true`.
4. Confira inventário, prévia, limites, fuso e agenda. O export usa uma rodada por hora, minuto 05, em UTC.
5. Após validar essas escolhas, altere `dryRun: false` e publique/ative o workflow na sua instalação.

Não há envio de teste por execução manual. A integração real precisa ser validada em uma instalação de teste com destinatário controlado. Gmail desabilitado ou sem confirmação não avança o registro de envio. A confirmação significa que o Gmail retornou um ID, sem prova de entrega na caixa do destinatário.

## Plano offline

Exporte um único item JSON da saída completa do nó **Avaliar evidencias**, antes do lote de notificações. O relatório precisa de `assets`, `findings`, `details` e `osvMatches`; a saída reduzida de **Resultado sem envio** não contém todas essas entradas.

```sh
node scripts/build-ciberia-offline-report.mjs --input local/evidence.json --output-dir local/report
```

O comando aceita um frame JSON ou `[{"json": frame}]`, trata o input como dados e gera `plan.json` e `plan.md`. Para conferir também a integridade dos lockfiles de um inventário:

```sh
node scripts/build-ciberia-offline-report.mjs --input local/evidence.json --output-dir local/verified-report --inventory local/inventory.json --root /caminho/do/seu/repositorio
```

A verificação confirma que os arquivos listados continuam com os hashes do inventário. Ela não autentica a origem do export nem prova que o inventário representa produção. Os comandos recusam sobrescrever saídas existentes; use outro arquivo ou diretório numa nova rodada.

Os candidatos abrangem altas/críticas conhecidas nos detalhes do snapshot, preservando múltiplas versões do mesmo pacote. Não consultam um registro de releases, não resolvem dependências e não garantem compatibilidade ou ausência de vulnerabilidades novas.

## Estado, retenção e falhas

A deduplicação usa `$getWorkflowStaticData`, recurso experimental do n8n. Não há lock ou garantia de entrega única: limite a uma execução de produção por vez. O ledger guarda até 20.000 chaves compactas e só avança o envio após confirmação do Gmail. Uma falha após a aceitação pode repetir uma mensagem.

Os HTTP nodes usam timeout de 30 segundos, lotes de três, limite de 10.000 consultas únicas, 500 detalhes OSV e até cinco páginas de PHP. Paginação incompleta, rate limit e falhas viram avisos de cobertura. Falha total do n8n, validação ou envio exige monitoramento externo/Error Workflow.

O export desliga o salvamento de execuções manuais, bem-sucedidas e com erro. Isso reduz persistência de relatórios, mas não remove configuração de workflow, credenciais, backups, logs ou dados já armazenados pela instalação. Defina a política de retenção do seu ambiente.

Referências: [Docker no n8n](https://docs.n8n.io/hosting/installation/docker/), [static data](https://docs.n8n.io/code/cookbook/builtin/get-workflow-static-data/) e [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/).
