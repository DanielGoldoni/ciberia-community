# Contribuir

Abra uma issue descrevendo o problema e a evidência esperada. Para alterações, crie uma branch e envie um PR pequeno com contexto e os comandos de validação executados.

```sh
npm run check
git diff -- workflows/ciberia.json
```

Edite a implementação em `scripts/`, não apenas o export gerado. Adicione regressões de comportamento com dados fictícios, especialmente para falsos positivos, faixas não suportadas, falhas de fonte e separação entre prévia e envio. Testes não devem consultar APIs reais nem enviar emails.

Não inclua inventários da sua organização, relatórios reais, arquivos `.env`, dumps do n8n, nomes de clientes ou referências de credenciais. Exemplos devem usar projetos inventados e `example.invalid`. Veja [a política de privacidade dos exemplos](docs/privacy.md).

As contribuições são recebidas sob a licença MIT deste repositório. Integrações externas continuam sujeitas aos seus próprios termos.
