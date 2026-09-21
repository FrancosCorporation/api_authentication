# api_authentication

## 🐳 Instalação e Execução (Docker) — recomendado

### Pré-requisitos
- [Docker](https://docs.docker.com/get-docker/) + Docker Compose

### Rodar com Docker
```bash
docker compose up --build
```
```bash
docker run --rm -v $(pwd):/src -w /src mcr.microsoft.com/dotnet/sdk:8.0 dotnet run
```

### Sem Docker (local)
```bash
# Requer .NET SDK
dotnet build
dotnet run
```

API REST de autenticação e cadastro multi-tenant de condomínios, com um banco MongoDB isolado por condomínio e autenticação por JWT com papéis.

![C#](https://img.shields.io/badge/C%23-239120?style=flat-square&logo=csharp&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-5.0-512BD4?style=flat-square&logo=dotnet&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=flat-square&logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=flat-square&logo=jsonwebtokens)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-em%20desenvolvimento-yellow?style=flat-square)

## Sobre

Serviço responsável pelo onboarding e pela autenticação de condomínios em uma plataforma condominial. Ao cadastrar um condomínio, a API cria um **banco de dados dedicado no MongoDB** (com coleções de usuários, configuração do app, academia e avisos) e registra o usuário administrador. A partir daí, o login devolve um token JWT cujas *claims* carregam o banco (`database`), o id do usuário (`objectId`) e o papel (`role`), permitindo que os demais serviços da plataforma roteiem a requisição para o banco correto.

## Funcionalidades

Comprovadas pelo código em `Controllers/` e `Services/`:

- `POST /api/RegisterUserAndCondominio` — cadastra usuário e cria o banco do condomínio com as coleções `users`, `config_app`, `academia` e `avisos`, gravando a senha como hash SHA-256.
- `POST /api/LoginCondominio` — autentica usuário no banco do condomínio informado e devolve token JWT (validade de 10 horas, claims `objectId`, `name`, `database` e `role`).
- `GET /api/myUser` — retorna o usuário autenticado; protegido por `[Authorize(Roles = "Administrator")]` e validado por token.
- `GET /api/databases` — lista os bancos de condomínios existentes (excluindo `admin`, `config` e `local`).
- `GET /api/databasename` — retorna o nome do banco configurado para o serviço.
- `GET /api/listcollection` — lista as coleções do banco configurado.
- `GET /api/usercollection?nameCondominio=` — lê a coleção de usuários de um condomínio.
- Rotas de exemplo em `v1/account` (`anonymous`, `authenticated`, `employee`, `manager`) demonstrando autorização anônima, autenticada e por papéis (`employee`, `manager`), com validação de token no endpoint `manager`.
- Hash de senha em SHA-256 (`Services/CondominioService.cs`) e geração/validação/parsing de JWT (`Services/TokenService.cs`).

## Stack

- **Linguagem/framework**: C# com ASP.NET Core 5.0 (Web API)
- **Banco de dados**: MongoDB (`MongoDB.Driver` 2.11.6), um banco por condomínio
- **Autenticação**: JWT (`Microsoft.AspNetCore.Authentication.JwtBearer` 5.0.3); pacotes `Microsoft.AspNetCore.Authentication.OpenIdConnect`, `Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.AspNetCore.Identity.UI`, `Microsoft.EntityFrameworkCore.*` e `Microsoft.Identity.Web` referenciados no `.csproj`
- **Documentação**: `Swashbuckle.AspNetCore` referenciado no `.csproj` (Swagger não é registrado no `Startup.cs` atual)

## Como rodar

Requer configuração de ambiente. Passos:

1. Instale o [.NET 5 SDK](https://dotnet.microsoft.com/download/dotnet/5.0).
2. Suba um MongoDB acessível (o `appsettings.json` aponta para `mongodb://localhost:27017`, banco `Condominios`).
3. Ajuste `appsettings.json` se necessário:

   ```json
   {
     "CondominioDatabaseSetting": {
       "ConnectionString": "mongodb://usuario:senha@host:27017",
       "DatabaseName": "Condominios"
     }
   }
   ```

4. Restaure e execute:

   ```bash
   dotnet restore
   dotnet run
   ```

O perfil `api_authentication` do `Properties/launchSettings.json` expõe a aplicação em `https://localhost:5003` e `http://localhost:5004`.

> O arquivo `Settings.cs` versionado contém uma chave JWT fixa (`Settings.Secret`) usada para assinar e validar os tokens. Trate-a como credencial de desenvolvimento e substitua por um segredo gerenciado fora do repositório em qualquer ambiente real. O `mongod.exe` (binário do MongoDB para Windows, ~36 MB) também está versionado na raiz.

## Estrutura do projeto

```
api_authentication/
├── Controllers/                # CondominioController (/api) e UserController (/v1/account)
├── Models/                     # UserCondominio, User, Users e CondominioDatabaseSetting
├── Repositories/               # UserRepository (usuários de exemplo para as rotas v1/account)
├── Services/                   # CondominioService (Mongo multi-tenant) e TokenService (JWT)
├── Properties/                 # launchSettings.json
├── Program.cs
├── Settings.cs                 # Chave de assinatura do JWT
├── Startup.cs                  # DI, autenticação JWT e pipeline HTTP
└── apiOAuth.csproj             # net5.0
```

## Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE).
