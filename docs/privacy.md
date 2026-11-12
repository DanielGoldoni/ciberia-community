# Privacidade e publicação de exemplos

## Mapa de código

- `scripts/prepare-ciberia-repository-config.mjs`: coleta versões e hashes; omite URLs de download e caminhos absolutos do inventário.
- `scripts/build-ciberia-v2.mjs`: define consultas externas, `aiFacts`, relatório e retenção do export.
- `.gitignore`: exclui diretórios locais de inventários, relatórios e dados n8n.
- `.github/workflows/checks.yml`: executa testes e Gitleaks sobre os arquivos da distribuição.

## Fluxo de dados

| Etapa | Dados utilizados ou transmitidos |
| --- | --- |
| Demonstração padrão | Apenas fixtures fictícias; nenhuma chamada externa do workflow |
| Coletor local | Nomes/versões de dependências, módulos e hashes; sem rede |
| OSV | Ecossistema, nome e versão de cada pacote consultado |
| GitHub/php.net | Consultas públicas de advisories/comunicados PHP; não recebem o inventário como payload |
| Gemini opcional | Até 25 alertas com IDs, pacotes, versões, títulos, classificações, ações e fontes; nomes de ativos/projetos não entram diretamente em `aiFacts` |
| Gmail configurado | Relatório com projetos, ambientes, ativos, versões e evidências |
| Plano offline | Export completo e, opcionalmente, lockfiles para conferir hashes; sem rede |

Mesmo sem campos de projeto, nomes de pacotes e textos livres podem revelar contexto. Habilite serviços externos somente para dados que sua organização autoriza compartilhar. Não coloque tokens, dados pessoais, URLs com credenciais ou informações de pacientes/clientes no inventário.

## Manter a distribuição genérica

Guarde configuração real, exports de execução e relatórios em `local/` ou em armazenamento privado fora do checkout. `.gitignore` ajuda a evitar adição acidental; não apaga arquivos já rastreados nem é uma barreira de acesso.

Não publique exports preenchidos, credenciais/referências de contas, `pinData`, static data, dumps/backups do n8n, arquivos `.env` ou relatórios de ambientes reais. Para uma contribuição ou captura pública, crie uma fixture nova com projetos fictícios, IDs `DEMO-*` e URLs `example.invalid`.

O export inicial não contém referências de credenciais nem inventário real. A configuração padrão desliga o salvamento de execuções. O n8n ainda armazena o próprio workflow e as credenciais que você configurar; suas políticas de logs, backups e retenção continuam necessárias.

Revise os arquivos antes de cada commit. O Gitleaks identifica padrões de segredos, mas não reconhece todo contexto confidencial. Se um segredo real for publicado, revogue-o/rotacione-o e trate também histórico, cópias e acessos; removê-lo do arquivo atual não elimina a exposição anterior.
