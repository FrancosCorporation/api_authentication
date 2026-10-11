# Política de segurança

## Reportar vulnerabilidades

Use [GitHub Security Advisories](https://github.com/FrancosCorporation/api_authentication/security/advisories/new)
para enviar um relato privado. Não publique tokens, dados de usuários, hashes de senha ou passos
exploráveis em uma issue pública.

## Escopo e limites

- O segredo que assina JWTs vem de `API_AUTHENTICATION_JWT_SECRET`, deve ter ao menos 32 bytes e
  não pode ser reutilizado entre ambientes.
- Uma chave JWT anterior foi incluída no histórico Git e deve ser considerada comprometida. O
  mantenedor precisa rotacioná-la em todos os ambientes e coordenar a limpeza do histórico/clones.
- Senhas novas usam BCrypt; hashes SHA-256 legados são migrados depois de um login correto.
- O banco indicado no login é um identificador de tenant: só nomes de bancos existentes e no
  formato permitido são aceitos, e o registro autenticado precisa declarar o mesmo tenant.
- O endpoint antigo `/api/usercollection`, que expunha registros com hashes, foi desativado.
- A lista de tentativas de login é local a cada instância. A revogação de tokens é compartilhada
  pelo MongoDB central configurado para a aplicação.

## Dados sensíveis

Não registre senhas, tokens ou hashes. Use TLS entre clientes, proxy e API; configure
`TRUSTED_PROXY_IPS` somente com endereços de proxies sob seu controle.
