# api_authentication

API REST de cadastro e autenticação de condomínios, com um banco MongoDB por tenant e tokens JWT.

![C#](https://img.shields.io/badge/C%23-239120?style=flat-square&logo=csharp&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-10-512BD4?style=flat-square&logo=dotnet&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=flat-square&logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=flat-square&logo=jsonwebtokens)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

## Requisitos

- .NET 10 SDK
- MongoDB acessível pela aplicação
- segredo JWT aleatório com pelo menos 32 bytes

O arquivo `.env.example` lista as variáveis usadas. O .NET não carrega arquivos `.env` automaticamente:

```bash
cp .env.example .env
# Preencha o segredo, depois carregue as variáveis no shell:
set -a
source .env
set +a
dotnet restore
ASPNETCORE_ENVIRONMENT=Development ASPNETCORE_URLS=http://localhost:5000 dotnet run --no-launch-profile
```

Para gerar um segredo local, use `openssl rand -hex 32` e coloque o resultado em
`API_AUTHENTICATION_JWT_SECRET`. Nunca versione `.env`.

## Rotas principais

| Método e rota | Acesso | Descrição |
|---|---|---|
| `POST /api/RegisterUserAndCondominio` | Público, limitado por IP | Cria o banco do tenant e seu primeiro administrador. Recebe formulário `username`, `password`, `nameCondominio` e `email`. |
| `POST /v1/account/login` | Público, limitado por IP e tentativas | Recebe JSON com `username`, `password` e `nameCondominio`; devolve JWT ou erro uniforme. |
| `POST /v1/account/logout` | JWT | Revoga o `jti` até o vencimento do token. |
| `GET /api/myUser` | Papel `Administrator` | Retorna o perfil do usuário autenticado sem dados de senha. |
| `GET /api/databases`, `/api/listcollection`, `/api/databasename` | Papel `Administrator` | Diagnóstico; `/api/databases` retorna só o tenant do token. |

Exemplo de login:

```bash
curl -X POST http://localhost:5000/v1/account/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"sua-senha","nameCondominio":"meu-condominio"}'
```

Tokens usam HS256, emissor e audiência fixos e vencem em 15 minutos. As senhas novas usam BCrypt
custo 12; senhas legadas SHA-256 são migradas para BCrypt no primeiro login correto. O banco do
tenant informado é validado contra os bancos existentes, e o usuário autenticado precisa pertencer
ao mesmo tenant. A antiga rota `/api/usercollection` foi desativada porque expunha registros de usuário.

O limite de login é mantido em memória por instância. Em produção com várias instâncias, configure
um gateway compartilhado para aplicar limites globais; o estado de revogação do JWT fica no MongoDB
central configurado em `CondominioDatabaseSetting`.

## Proxy e HTTPS

Em produção, publique a API por HTTPS. HSTS fica ativo fora do ambiente `Development`. Se houver
proxy reverso, informe apenas os IPs confiáveis em `TRUSTED_PROXY_IPS`, separados por vírgula; a API
aceita `X-Forwarded-For` e `X-Forwarded-Proto` desses proxies.

## Credencial histórica

Uma chave JWT anterior foi incluída no histórico deste repositório e deve ser tratada como
comprometida. Não reutilize essa chave. Antes de implantar, configure um segredo novo em todos os
ambientes e invalide tokens antigos; a remoção da chave do histórico Git ainda exige uma reescrita
coordenada do histórico e atualização dos clones.

## Segurança e licença

Consulte [SECURITY.md](SECURITY.md) para o canal de reporte. Licença MIT em [LICENSE](LICENSE).
