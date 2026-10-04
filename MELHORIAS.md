# MELHORIAS — api_authentication

> **Gerado por análise de código em 2026-10-02** · Stack: .NET 5 (ASP.NET Core, JWT Bearer, MongoDB)
> Branch `master` · base `149a5f2` · 621 LOC · **0 testes** · 15 arquivos de código
>
> **Este arquivo é um plano de execução.** Cada item tem ID, `arquivo:linha`, mudança exata,
> critério de aceite e comando de verificação. Nada aqui é genérico: tudo foi lido no código.

---

## 0. Como usar este documento

1. Execute na ordem **P0 → P1 → P2 → P3**, respeitando as ondas da §8.
2. Ao terminar um item: marque `- [x]`, rode o **Verificação**, comite `fix(<ID>): descrição`.
3. **Não** troque a biblioteca de auth. O projeto usa `JwtBearer` corretamente; os defeitos são
   de *configuração e de código morto*, não de arquitetura.
4. **Idioma:** mantenha português em comentários e respostas (padrão do repositório).
   Commits em inglês com prefixo `fix:`/`feat:`/`docs:`, conforme o histórico.
5. Este projeto tem defeito de compilação (`BUG-00`). Faça `BUG-00` antes de qualquer outro item.

---

## 1. Diagnóstico executivo

API REST de autenticação para plataforma de condomínios multi-tenant: valida usuário contra MongoDB
e emite JWT com as claims `objectId`, `name`, `database` (condomínio) e `role`. Essa claim `database`
é a fronteira de isolamento entre tenants — se ela puder ser forjada, um condomínio lê o outro.

A estrutura de pastas está correta e a DI está bem montada. O problema é que a segurança foi
desativada por conveniência em quatro pontos independentes: a **chave de assinatura está escrita no
código-fonte e no histórico do GitHub**, o **endpoint de login está inteiramente comentado**, o
**validador de token acessa o array sem verificar tamanho**, e o **caminho de senha usa SHA-256 cru**.

O login real está em `CondominioService.loginCondominio` (linha 82 de `CondominioService.cs`), que
faz `ToList()[0]` sem checar se a lista é vazia — **usuário inexistente estoura exceção**. E
`RegisterUserAndCreateDatabase` (linha 68) engole **toda** exceção devolvendo uma string genérica
com HTTP 200, escondendo falhas de configuração.

**Resumo executivo:** em produção, quem ler o repositório forja token de administrador para
qualquer condomínio em segundos. Os itens P0 abaixo fecham isso sem reescrever a API.

---

## 2. Tabela de prioridades

| ID | Título | Sev | Arquivo | Depende de |
|---|---|---|---|---|
| BUG-00 | `&` no lugar de `&&` (comportamento indefinido) | **P0** | `CondominioService.cs:82` | — |
| SEC-01 | chave JWT removida do código + rotação | **P0** | `Settings.cs:6` | — |
| SEC-08 | senha comparada a si mesma (bypass total) | **P0** | `UserRepository.cs:14` | — |
| BUG-01 | login commented out: **não existe endpoint** | **P0** | `UserController.cs:19-38` | BUG-00, SEC-01, SEC-08 |
| BUG-02 | usuário inexistente estoura exceção | **P1** | `CondominioService.cs:82` | BUG-00 |
| BUG-05 | cliente escolhe o nome do banco (tenant) | **P1** | `CondominioService.cs:80` | — |
| SEC-03 | SHA-256 cru no lugar de bcrypt/Argon2 | **P1** | `CondominioService.cs:49,78` | — |
| SEC-02 | `ValidateToken` estoura sem header | **P1** | `TokenService.cs:39,74` | — |
| SEC-04 | rate limit / lockout no login | **P1** | `CondominioService.cs:75` | BUG-01 |
| SEC-05 | validar `issuer`/`audience` | **P1** | `Startup.cs:57` | SEC-01 |
| SEC-06 | segredo aceito com qualquer tamanho | **P1** | `Startup.cs:44` | SEC-01 |
| SEC-07 | sem HSTS + `RequireHttpsMetadata:false` | **P1** | `Startup.cs:51,72` | — |
| BUG-03 | `catch` engole toda exceção (config/banco) | **P1** | `CondominioService.cs:68` | — |
| TEST-01 | suíte do serviço de token | **P1** | novo `tests/` | SEC-01, SEC-05 |
| TEST-02 | teste de integração do login | **P1** | novo `tests/` | BUG-01, SEC-04 |
| DEVOPS-01 | .NET 5 EOL → .NET 8 LTS | **P1** | `apiOAuth.csproj:4` | BUG-00 |
| DEVOPS-03 | CVEs nos pacotes `5.0.3` | **P1** | `apiOAuth.csproj` | DEVOPS-01 |
| BUG-04 | cadastro de condomínio não é atômico | **P2** | `CondominioService.cs:50-64` | — |
| IMP-01 | token sem `jti` (sem revogação) | **P2** | `TokenService.cs:21` | SEC-01 |
| IMP-02 | validade 10 h sem refresh token | **P2** | `TokenService.cs:30` | SEC-01 |
| IMP-03 | resposta de login não é uniforme | **P2** | `CondominioService.cs:90` | — |
| IMP-04 | `dynamic` no serviço de token | **P2** | `TokenService.cs:37,72` | — |
| DEVOPS-02 | `obj/` versionado no git | **P2** | `.gitignore` | — |
| DEVOPS-04 | CI: build + teste | **P2** | novo `.github/workflows/ci.yml` | TEST-01 |
| DEVOPS-05 | falta `.env.example` | **P2** | novo | SEC-01 |
| DOC-01 | README não documenta variáveis de ambiente | **P2** | `README.md` | SEC-01 |
| DOC-02 | falta `SECURITY.md` | **P3** | novo | — |

**Totais: 4 P0 · 10 P1 · 8 P2 · 1 P3 = 27 itens.**

---

## 3. Segurança

### SEC-08 · Senha comparada a si mesma no repositório · [P0]

- **Arquivo:** `Repositories/UserRepository.cs:14`
- **Evidência:**
  ```csharp
  return users.Where(x => x.Username.ToLower() == username.ToLower()
                         && x.Password == x.Password).FirstOrDefault();
  ```
  O predicado termina em `x.Password == x.Password` — **sempre verdadeiro**. A senha recebida do
  cliente **nunca é comparada**. Os usuários de teste (`batman`/`batman`, `robin`/`robin`, linhas
  12-13) entram com qualquer senha, desde que o username exista.
- **Impacto:** bypass total de autenticação. `username=batman` + `password=qualquer-coisa`
  autentica como `manager`. É o pior bug possível numa API cujo único propósito é autenticar.
- **Mudança:** (1) **remover `UserRepository`** — é herança de tutorial e o único caller
  (`UserController.cs:25`) está dentro do bloco comentado que `BUG-01` elimina; (2) se for mantido
  para testes, comparar em tempo constante:
  ```csharp
  CryptographicOperations.FixedTimeEquals(
      Encoding.UTF8.GetBytes(x.Password), Encoding.UTF8.GetBytes(password))
  ```
  (3) nunca hardcodear usuários em código de produção.
- **Aceite:** `batman`/`senhaerrada` **não** autentica; `grep "== x.Password"` retorna vazio.
- **Verificação:**
  ```bash
  grep -rn "== x.Password" Repositories/ Services/ && echo FALHA || echo OK
  dotnet build
  ```

### SEC-01 · Chave JWT removida do código + rotação · [P0]

- **Arquivo:** `Settings.cs:6`
- **Evidência:** `public static string Secret = "fedaf7d8863b48e197b9287d492b708e";` — literal em
  arquivo versionado, consumido por `Startup.cs:44` e `TokenService.cs:20,49`.
- **Impacto:** a chave está no histórico público em `github.com/FrancosCorporation/api_authentication`.
  Quem lê o código forja token com `role=manager` e `database=<qualquer tenant>` em segundos.
  Apagar o arquivo **não** resolve: é preciso **rotacionar** e reescrever o histórico.
- **Mudança:**
  1. Trocar por variável de ambiente, espelhando `condominio_api/Config/Settings.cs:19`:
     ```csharp
     public static string Secret =>
         Environment.GetEnvironmentVariable("API_AUTHENTICATION_JWT_SECRET")
         ?? throw new InvalidOperationException(
             "API_AUTHENTICATION_JWT_SECRET nao definida. Exporte a variavel antes de iniciar.");
     ```
     Use **`throw`**, não fallback: um valor padrão silencioso é exatamente o que cria o risco.
  2. **Rotacionar** `fedaf7d8...` — considerar comprometido para sempre.
  3. Remover o literal do histórico: `git filter-repo --path Settings.cs --invert-paths`,
     depois `git push --force-with-lease`.
- **Aceite:** nenhum literal hex em código; a API falha ao subir sem a variável; token assinado
  com a chave antiga é rejeitado.
- **Verificação:**
  ```bash
  grep -rn "fedaf7d8863b48e197b9287d492b708e" . --include='*.cs' && echo FALHA || echo OK
  API_AUTHENTICATION_JWT_SECRET=$(openssl rand -hex 32) dotnet run   # sobe
  dotnet run                                                         # falha com mensagem clara
  ```

### SEC-03 · SHA-256 cru no lugar de bcrypt/Argon2 · [P1]

- **Arquivo:** `Services/CondominioService.cs:49` (cadastro) e `:78` (login)
- **Evidência:** `string _passwordSHA256 = passToHash(password: password);` — hash **sem sal**,
  SHA-256 (via `System.Security.Cryptography`, importado na linha 6).
- **Impacto:** SHA-256 sem sal é quebrado por GPU (bilhões de tentativas/s por senha). Um dump de
  qualquer condomínio vira dicionário em minutos. Sem sal, senhas iguais geram hash igual.
- **Mudança:**
  1. Trocar `passToHash` por `BCrypt.Net-Next` (ou Argon2), custo **≥ 12**:
     `BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12)`.
  2. Gravar marcador de versão no documento (`"alg": "bcrypt12"`) para saber qual verificador usar.
     Sem isso os hashes SHA-256 antigos ficam órfãos e ninguém mais entra.
  3. Manter `passToHash` **somente** para validar legados e, no primeiro login bem-sucedido,
     **re-hashear** com bcrypt e salvar (migração transparente).
- **Aceite:** o banco passa a guardar bcrypt de custo ≥ 12; dois usuários com a mesma senha têm
  hashes diferentes; SHA-256 não aparece no caminho de login novo.
- **Verificação:**
  ```bash
  grep -rn "passToHash" Services/   # deve existir só no caminho de migração legada
  mongo --eval 'db.users.findOne({}, {username:1,password:1})'   # hash $2a$/$2b$
  ```

### SEC-05 · Validar `issuer` e `audience` · [P1]

- **Arquivo:** `Startup.cs:57-58` e `TokenService.cs:45-48`
- **Evidência:** `ValidateIssuer = false` e `ValidateAudience = false`, com o comentário
  `"Because there is no audiance in the generated token"`. Mas o token **também** não é gerado com
  `Issuer`/`Audience` (`TokenService.cs:21-32` define só `Subject`, `Expires`, `SigningCredentials`).
- **Impacto:** qualquer serviço que use a **mesma chave** e o mesmo formato de token é aceito por
  esta API — vetor clássico de *token confusion*. Como a chave é pública (SEC-01), isso agrava.
- **Mudança:**
  1. Em `TokenService.GenerateToken`, adicionar `Issuer = "api_authentication"` e
     `Audience = "condominio_api"` ao `SecurityTokenDescriptor`.
  2. Em `Startup.cs:53-59` e `TokenService.cs:42-58`, usar
     `ValidateIssuer = true, ValidIssuer = "api_authentication"` e
     `ValidateAudience = true, ValidAudience = "condominio_api"`.
  3. Extrair `Issuer`/`Audience` para `Settings` — hoje os dois arquivos de validação **duplicam**
     os parâmetros e podem divergir silenciosamente (ver `IMP-04`).
- **Aceite:** token assinado com a mesma chave mas sem `iss`/`aud` é rejeitado com `401`.
- **Verificação:** coberto por `TEST-01` (caso "issuer ausente rejeita").

### SEC-02 · `ValidateToken` estoura sem header `Authorization` · [P1]

- **Arquivo:** `Services/TokenService.cs:39` e `:74`
- **Evidência:** `string jwtString = request.Headers["Authorization"].ToString().Split(" ")[1];`
  Sem header → string vazia → `Split(" ")` devolve array de **1** elemento → índice `[1]` lança
  `IndexOutOfRangeException`. O `try/catch` da linha 60 captura apenas `SecurityTokenException`,
  então a exceção escapa. Mesmo problema em `UnGenereteToken` (linha 74).
- **Impacto:** requisição anônima sem header (bot, scanner, curl) derruba o middleware com `500`
  em vez de `401` — DoS trivial e poluição de log com stack trace.
- **Mudança:** validar antes de indexar, com o mesmo tratamento nos dois métodos:
  ```csharp
  private static bool TryExtractBearer(HttpRequest request, out string token) {
      var header = request.Headers["Authorization"].ToString();
      token = null;
      if (string.IsNullOrWhiteSpace(header)) return false;
      if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
      token = header["Bearer ".Length..].Trim();
      return !string.IsNullOrWhiteSpace(token);
  }
  ```
  `ValidateToken` devolve `false`; `UnGenereteToken` devolve `null`.
- **Aceite:** rota protegida sem header devolve `401`, **não** `500`; nenhum
  `IndexOutOfRangeException` no log.
- **Verificação:**
  ```bash
  curl -i http://localhost:5000/v1/account/authenticated                            # 401
  curl -i -H 'Authorization: Bearer' http://localhost:5000/v1/account/authenticated # 401
  ```

### SEC-04 · Rate limit e lockout no login · [P1]

- **Arquivo:** `Services/CondominioService.cs:75-91`
- **Evidência:** `loginCondominio` consulta o Mongo e responde sem nenhum contador de tentativas.
  Não há `AddRateLimiter`, nem `appsettings` de limite, nem bloqueio progressivo no projeto.
- **Impacto:** brute-force ilimitado. Com bcrypt de custo 12 (após `SEC-03`) o atacante fica mais
  lento, mas ainda dispara milhares de requisições em paralelo.
- **Mudança:**
  1. Rate limit no login: **5 tentativas por (usuário, tenant) a cada 5 min**; limite por IP mais
     frouxo (ex.: 20/5 min) para a conta não virar alvo de DoS.
  2. Responder `429` com `Retry-After` ao exceder.
  3. Resposta **uniforme** (ver `IMP-03`): login inválido devolve sempre `401` com a mesma mensagem.
  4. Logar IP + usuário + resultado, **nunca** a senha.
- **Aceite:** o 6º login errado em 5 min devolve `429`; usuário inexistente também (sem oráculo).
- **Verificação:**
  ```bash
  for i in $(seq 1 7); do
    curl -s -o /dev/null -w "tentativa $i -> %{http_code}\n" -X POST \
      http://localhost:5000/v1/account/login -H 'Content-Type: application/json' \
      -d '{"username":"alvo","password":"errada","nameCondominio":"tenant"}'
  done
  # esperado: 401 x5, depois 429
  ```

### SEC-06 · Segredo aceito com qualquer tamanho · [P1]

- **Arquivo:** `Startup.cs:44` e `TokenService.cs:20`
- **Evidência:** `Encoding.ASCII.GetBytes(Settings.Secret)` sem validar tamanho. HS256 aceita chave
  de qualquer comprimento, e `ASCII.GetBytes` **trunca silenciosamente** bytes acima de 0x7F — uma
  chave colada no env perde o final sem aviso.
- **Impacto:** segredo curto (ex.: `"x"`) torna o brute-force trivial; segredo com caractere não-ASCII
  é truncado, reduzindo a entropia sem erro visível.
- **Mudança:** validar na inicialização (fail-fast) que o segredo tem **≥ 32 bytes**; usar
  `Encoding.UTF8` nos dois pontos de consumo; registrar o **comprimento** (não o valor) no log de start.
- **Aceite:** a API não inicia com segredo < 32 bytes; o log de erro diz isso explicitamente.
- **Verificação:**
  ```bash
  API_AUTHENTICATION_JWT_SECRET=curta dotnet run   # recusa com mensagem sobre o tamanho mínimo
  ```

### SEC-07 · Sem HSTS e `RequireHttpsMetadata:false` · [P1]

- **Arquivo:** `Startup.cs:51` e `:72`
- **Evidência:** coexistem `app.UseHttpsRedirection()` (linha 72) e
  `x.RequireHttpsMetadata = false` (linha 51). **Não há `UseHsts()`** em lugar nenhum do projeto.
- **Impacto:** sem HSTS, o primeiro acesso pode ocorrer em HTTP claro e o token trafega em texto.
  `RequireHttpsMetadata=false` em produção sugere TLS desligado em algum estágio.
- **Mudança:** (1) `app.UseHsts()` antes de `UseRouting()` quando `!env.IsDevelopment()`;
  (2) `RequireHttpsMetadata = !env.IsDevelopment()` (injetar `IWebHostEnvironment` em
  `ConfigureServices`); (3) se houver proxy TLS na frente, configurar `ForwardedHeaders` com
  `X-Forwarded-Proto`, senão o `UseHttpsRedirection` entra em loop.
- **Aceite:** resposta em produção traz `Strict-Transport-Security`; sem loop de redirect atrás do proxy.
- **Verificação:**
  ```bash
  curl -sI https://<host-producao>/v1/account/authenticated | grep -i strict-transport-security
  ```

---

## 4. Bugs e defeitos funcionais

### BUG-00 · `&` no lugar de `&&`: comparação sem curto-circuito · [P0]

- **Arquivo:** `Services/CondominioService.cs:82`
- **Evidência:**
  ```csharp
  UserCondominio _user = _users.Find(_user => _user.username == user.username
                                             & _user.password == _passwordSHA256).ToList()[0];
  ```
  O operador é `&` (bitwise) e **não** `&&` (lógico). Em C#, `bool & bool` é bitwise e não faz
  curto-circuito.
- **Impacto:** (a) a comparação de senha é **sempre** avaliada, mesmo quando o usuário não bate;
  (b) combinado com `BUG-02`, o `ToList()[0]` estoura. O `&` também mascara a intenção: o autor
  provavelmente queria `&&` e nunca testou esse caminho.
- **Mudança:** trocar `&` por `&&`.
- **Aceite:** `dotnet build` sem erro; a comparação de senha só é avaliada quando o username bate.
- **Verificação:**
  ```bash
  grep -n "user.username" Services/CondominioService.cs    # localizar a linha
  # trocar o & por &&
  dotnet build     # 0 erros
  ```

### BUG-01 · Endpoint de login está inteiramente comentado · [P0]

- **Arquivo:** `Controllers/UserController.cs:19-38`
- **Evidência:** todo o método `Authenticate` está dentro de `/* ... */` (linhas 19-38). As únicas
  rotas ativas são `anonymous` (l.39), `authenticated` (l.44), `employee` (l.49) e `manager` (l.54) —
  todas exigem token, mas **não existe rota que produza o token**.
- **Impacto:** a API **não é utilizável** — ninguém consegue obter token. Pior: o código comentado
  chama `UserRepository.Get(...)`, justamente o arquivo com o bypass `SEC-08`. Um "descomentar para
  testar" reintroduz o bypass silenciosamente.
- **Mudança:**
  1. **Não** simplesmente descomentar. O login real já existe em `CondominioService.loginCondominio`
     (linha 75) e é superior (Mongo real em vez de lista hardcoded).
  2. Escrever a rota nova, ligada ao serviço real:
     ```csharp
     [HttpPost]
     [Route("login")]
     [AllowAnonymous]
     public async Task<ActionResult<dynamic>> Login([FromBody] UserCondominio model) {
         var resultado = _service.loginCondominio(model);
         if (resultado is UnauthorizedResult) return Unauthorized(new { message = "Credenciais invalidas" });
         return Ok(resultado.Value);
     }
     ```
  3. Adicionar rate limit (`SEC-04`) e resposta uniforme (`IMP-03`).
  4. Apagar o bloco comentado e o arquivo `UserRepository.cs` (`SEC-08`).
- **Aceite:** `POST /v1/account/login` com credenciais válidas devolve `200` + token; inválidas
  devolvem `401` com mensagem genérica; não resta bloco comentado no controller.
- **Verificação:**
  ```bash
  grep -n '/\*' Controllers/UserController.cs && echo "ainda tem comentario" || echo OK
  curl -X POST http://localhost:5000/v1/account/login -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"senha","nameCondominio":"tenant"}'
  ```

### BUG-02 · Usuário inexistente estoura exceção em vez de 401 · [P1]

- **Arquivo:** `Services/CondominioService.cs:82`
- **Evidência:** `...ToList()[0]` sem verificar se a lista está vazia. Usuário inexistente →
  `ToList()` devolve lista vazia → índice `[0]` lança `ArgumentOutOfRangeException`.
- **Impacto:** login de usuário inexistente produz `500` + stack trace no log, em vez de `401`.
  Isso vaza informação (o atacante distingue "não existe" de "senha errada" pelo status code) e
  enche o log de ruído — também facilita DoS por volume.
- **Mudança:**
  ```csharp
  var encontrado = _users.Find(x => x.username == user.Username && x.password == hash).FirstOrDefault();
  if (encontrado == null) return Unauthorized();   // resposta uniforme
  ```
  (junto com `BUG-00`, que troca `&` por `&&`).
- **Aceite:** login com usuário inexistente devolve `401`, sem exceção no log.
- **Verificação:**
  ```bash
  curl -i -X POST http://localhost:5000/v1/account/login -H 'Content-Type: application/json' \
    -d '{"username":"naoexiste","password":"x","nameCondominio":"tenant"}'   # 401, não 500
  ```

### BUG-05 · Cliente escolhe o nome do banco (isolamento de tenant) · [P1]

- **Arquivo:** `Services/CondominioService.cs:80`
- **Evidência:** `IMongoDatabase _newDatabase = _clientMongoDb.GetDatabase(user.nameCondominio);`
  — o nome do banco vem **direto do corpo da requisição**.
- **Impacto:** um cliente pode mandar `nameCondominio: "admin"` ou o nome de **outro** condomínio e
  tentar logar contra o banco dele. Se o `username` existir lá, o atacante obtém token com a claim
  `database` do tenant vítima. Esta é a falha de isolamento multi-tenant.
- **Mudança:** (1) resolver o tenant **no servidor**: mapear via `CondominioController` (existe) →
  banco, e validar que o usuário pertence ao tenant do token; (2) validar `nameCondominio` contra
  allowlist derivada de `GetListNameDatabase()` (`CondominioService.cs:28`) ou de um registro de
  tenants; (3) nunca confiar no nome de banco vindo do cliente para selecionar contexto.
- **Aceite:** `POST /login` com `nameCondominio` de outro tenant devolve `401` e **não** emite token.
- **Verificação:**
  ```bash
  curl -i -X POST http://localhost:5000/v1/account/login -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"<senha do tenant alvo>","nameCondominio":"<outro tenant>"}'
  # esperado 401
  ```

### BUG-03 · `catch` engole toda exceção e devolve 200 · [P1]

- **Arquivo:** `Services/CondominioService.cs:68-71`
- **Evidência:**
  ```csharp
  catch (System.Exception) {
      return "Não foi possivel realizar o cadastro, tente novamente mais tarde.";
  }
  ```
  Captura **tudo** e devolve uma **string** (HTTP 200). Nome de condomínio inválido, Mongo fora do
  ar, credencial errada e bug de programação ficam indistinguíveis do cliente.
- **Impacto:** falha silenciosa. O cadastro que falha reporta sucesso; o usuário só descobre ao
  tentar logar. Erros de configuração (ex.: `ConnectionString` vazia) ficam invisíveis.
- **Mudança:**
  1. Capturar só o esperado:
     `catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)`.
  2. **Logar** a exceção real via `ILogger<CondominioService>` (injetado no construtor) — hoje só
     existe `Console.Write(e)` (linha 89), e apenas no login.
  3. Traduzir para status HTTP: `409` duplicado, `503` banco indisponível, `500` inesperado.
  4. Remover `catch (SystemException)` do login (linha 87): é genérica demais e mascara o
     `ArgumentOutOfRangeException` de `BUG-02` como se fosse "credencial inválida".
- **Aceite:** falha no cadastro devolve status ≠ 200 **e** gera log com a exceção real.
- **Verificação:**
  ```bash
  grep -n "catch (SystemException)\|catch (System.Exception)" Services/CondominioService.cs  # deve sumir
  # derrubar o mongo e tentar cadastrar: esperado 503/500 com log no servidor
  ```

### BUG-04 · Cadastro de condomínio não é atômico · [P2]

- **Arquivo:** `Services/CondominioService.cs:50-64`
- **Evidência:** cria 3 coleções (`CreateCollection` ×3) e **depois** insere o usuário. Sem transação.
- **Impacto:** se o `InsertOne` falhar (e-mail duplicado, rede), ficam coleções vazias órfãs. O
  condomínio aparece em `GetListNameDatabase()` (linha 28) mas sem admin — estado inconsistente que
  ninguém usa nem remove pela API.
- **Mudança:** (1) usar `session.WithTransactionAsync` (exige replica set, muda o setup de dev);
  (2) alternativa mais simples e suficiente: **validar duplicidade antes** de criar coleções e, se o
  insert falhar, dropar as coleções criadas no `catch`; (3) registrar o tenant numa coleção central
  `tenants` como fonte de verdade.
- **Aceite:** falha no insert não deixa banco sem admin; ou o cadastro é completo, ou não existe.
- **Verificação:**
  ```bash
  # cadastrar 2x o mesmo condominio e conferir a listagem
  curl http://localhost:5000/v1/condominio   # nao pode listar condominio sem admin
  ```

---

## 5. Qualidade: testes, arquitetura e observabilidade

### IMP-01 · Token sem `jti` — impossível revogar · [P2]

- **Arquivo:** `Services/TokenService.cs:21-32`
- **Evidência:** o `SecurityTokenDescriptor` define `Subject`, `Expires` e `SigningCredentials`.
  Não há `Id`, logo o token não tem claim `jti`.
- **Impacto:** um token emitido não pode ser invalidado antes de `Expires`. Se o cliente rodar
  malicioso ou a senha for trocada, o token continua válido por **10 horas** (`IMP-02`).
- **Mudança:** `Id = Guid.NewGuid().ToString()` no descriptor; manter denylist de `jti` revogados
  (Redis ou coleção) com TTL até expirar. Adicionar `POST /v1/account/logout` que revoga.
- **Aceite:** token gerado tem `jti`; após `logout`, o mesmo token é rejeitado antes de expirar.
- **Verificação:**
  ```bash
  node -e "console.log(!!JSON.parse(Buffer.from(process.argv[1].split('.')[1],'base64')).jti)" "$TOKEN"
  ```

### IMP-02 · Validade de 10 h sem refresh token · [P2]

- **Arquivo:** `Services/TokenService.cs:30` (`Expires = DateTime.UtcNow.AddHours(10)`)
- **Evidência:** validade fixa de 10 h, sem refresh e sem revogação (`IMP-01`).
- **Impacto:** janela longa de exposição; o usuário precisa relogar a cada 10 h. O par "10 h + sem
  revogação" é o que torna qualquer vazamento caro.
- **Mudança:** access token curto (**15 min**) + refresh token de longa duração com rotação e
  revogação por família. Se o escopo for estudo, ao menos reduzir para 1 h e implementar logout.
- **Aceite:** token expirado exige re-autenticação; nenhum access token vive mais de 15 min.
- **Verificação:** decodificar `exp - iat` e confirmar o novo intervalo.

### IMP-03 · Resposta de login não é uniforme · [P2]

- **Arquivo:** `Services/CondominioService.cs:87-90`
- **Evidência:** o `catch` devolve `Unauthorized()` genérico, mas não há padronização de corpo nem
  de tempo entre os caminhos de falha.
- **Impacto:** diferença de tempo entre "usuário não existe" e "senha errada" permite
  **enumeração de usuários**.
- **Mudança:** resposta idêntica em toda falha — mesmo status, mesmo corpo, mesmo tempo. Considerar
  comparação contra hash **dummy** quando o usuário não existe, para igualar o tempo de resposta.
- **Aceite:** mesmo status e corpo para usuário inexistente, senha errada e tenant inválido.
- **Verificação:**
  ```bash
  for u in naoexiste admin; do
    curl -s -o /dev/null -w "$u -> %{http_code} %{time_total}s\n" -X POST \
      http://localhost:5000/v1/account/login -H 'Content-Type: application/json' \
      -d "{\"username\":\"$u\",\"password\":\"errada\",\"nameCondominio\":\"tenant\"}"
  done   # tempos próximos
  ```

### IMP-04 · `dynamic` no serviço de token · [P2]

- **Arquivo:** `Services/TokenService.cs:37` (`ValidateToken`), `:72` (`UnGenereteToken`) e
  `Services/CondominioService.cs:75` (`loginCondominio`)
- **Evidência:** retorno `dynamic` onde `bool`, `JObject?` e `ActionResult<TokenResponse>` bastariam.
- **Impacto:** erros só aparecem em runtime; o compilador não ajuda; `UserController.cs:59`
  (`if(isValid)`) aceita qualquer valor truthy — um objeto vazio passaria como "válido".
- **Mudança:** tipar explicitamente: `bool ValidateToken(...)`, `JObject? UnGenereteToken(...)`,
  `ActionResult<TokenResponse> loginCondominio(...)`, com DTO
  `TokenResponse { token, expiresAt, user }`.
- **Aceite:** nenhum `dynamic` no fluxo de autenticação; `if (isValid)` só aceita `bool`.
- **Verificação:** `grep -rn "dynamic" Services/ Controllers/` → sem ocorrências no fluxo de auth.

### TEST-01 · Suíte de teste do serviço de token · [P1]

- **Arquivo:** novo `tests/TokenServiceTests.cs` + `.csproj` de teste
- **Evidência:** o projeto tem **0 testes** (confirmado por inventário) e o `.gitignore:10` já
  referencia `TestResults/`, pressupondo que existe uma suíte.
- **Impacto:** todo o caminho de autenticação (§3) pode regredir silenciosamente. Foi exatamente
  isso que deixou o bypass `SEC-08` e o login comentado `BUG-01` passarem despercebidos: sem teste,
  ninguém percebe que a rota que emite token não existe.
- **Cobertura mínima obrigatória:**

  | Caso | Assertivo esperado |
  |---|---|
  | `GenerateToken` com usuário válido | token com `sub`, `role`, `database`, `jti`, `exp` |
  | Token expirado | `ValidateToken` → `false` |
  | Token assinado com outra chave | `false` |
  | Token **sem** `iss`/`aud` | `false` (após `SEC-05`) |
  | Header ausente / `"Bearer"` sem token | `false`, **sem exceção** (após `SEC-02`) |
  | Segredo com 16 bytes | API/validador recusa (após `SEC-06`) |

- **Mudança:** criar `api_authentication.Tests.csproj` (xUnit), injetar segredo de teste por
  variável de ambiente no fixture e cobrir a tabela acima.
- **Aceite:** `dotnet test` passa com ≥ 6 casos; falha se alguém reintroduzir segredo hardcoded.
- **Verificação:**
  ```bash
  dotnet test    # >= 6 testes, 0 falhas
  ```

### TEST-02 · Teste de integração do login · [P1]

- **Arquivo:** novo `tests/LoginIntegrationTests.cs`
- **Evidência:** o fluxo de login (`BUG-01` → `SEC-04` → `BUG-02` → `BUG-05`) é o caminho mais
  sensível da API e não tem nenhum teste.
- **Impacto:** os quatro defeitos mais graves (`SEC-08`, `BUG-01`, `BUG-02`, `BUG-05`) vivem
  exatamente neste fluxo. Sem teste de integração, qualquer refactor pode reintroduzi-los.
- **Cobertura mínima:** login válido → 200 + token utilizável; senha errada → 401 **uniforme**;
  usuário inexistente → 401 **idêntico** ao anterior; tenant de outro condomínio → 401 (`BUG-05`);
  6ª tentativa em 5 min → 429 (`SEC-04`); token expirado → 401.
- **Mudança:** usar `WebApplicationFactory` com Mongo de teste em memória ou em container.
- **Aceite:** `dotnet test` passa; medindo o tempo das respostas, "inexistente" e "senha errada"
  ficam dentro de ±20%.
- **Verificação:**
  ```bash
  dotnet test
  ```

---

## 6. DevOps / Infra

### DEVOPS-01 · .NET 5 está EOL — subir para .NET 8 LTS · [P1]

- **Arquivo:** `apiOAuth.csproj:4`
- **Evidência:** `<TargetFramework>net5.0</TargetFramework>`. O .NET 5 (maio/2021) está **fora de
  suporte desde 10/05/2022** — sem correções de segurança.
- **Impacto:** a API roda num framework sem patch; todo CVE de runtime permanece aberto.
- **Mudança:** (1) mudar para `net8.0` (LTS); (2) atualizar os `PackageReference` `5.0.3` → `8.0.x`
  (`DEVOPS-03`); (3) `Startup.cs`/`Program.cs` usam `Host.CreateDefaultBuilder`, padrão compatível —
  migração direta; (4) `MongoDB.Driver 2.11.6` → versão atual.
- **Aceite:** `dotnet build` compila em `net8.0`; a API sobe e autentica.
- **Verificação:**
  ```bash
  sed -i 's|net5.0|net8.0|' apiOAuth.csproj
  dotnet restore && dotnet build && dotnet test
  dotnet --list-runtimes | grep 8.0
  ```

### DEVOPS-03 · CVEs nos pacotes `5.0.3` · [P1]

- **Arquivo:** `apiOAuth.csproj:9-28`
- **Evidência:** 8 pacotes na versão `5.0.3`, `Microsoft.Identity.Web 1.1.0`,
  `Swashbuckle 5.6.3`. O GitHub já sinalizou vulnerabilidades neste repositório (registrado em
  `.planning/2026-09-21-containerizacao-dos-74-repos/findings.md:86`: "2 high, 2 moderate").
- **Impacto:** `JwtBearer` e `OpenIdConnect` em versão antiga podem ter falha de parsing de token —
  justamente o componente que valida credenciais.
- **Mudança:** após `DEVOPS-01`, alinhar tudo em `8.0.x`; rodar
  `dotnet list package --vulnerable --include-transitive` e eliminar cada achado; **remover pacotes
  não usados** (`Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Identity.UI`,
  `EntityFrameworkCore.Tools`, `VisualStudio.Web.CodeGeneration.Design` — o projeto usa **MongoDB**,
  não EF Core; os pacotes de Identity são resíduo do template).
- **Aceite:** `dotnet list package --vulnerable` retorna vazio; o número de pacotes cai de ~10 para ~5.
- **Verificação:**
  ```bash
  dotnet list package --vulnerable --include-transitive
  dotnet list package | wc -l
  ```

### DEVOPS-02 · `obj/` versionado no repositório · [P2]

- **Arquivo:** `.gitignore:2` já tem `[Oo]bj/` — mas os artefatos **já estão commitados**
  (confirmado no inventário: `obj/Debug/net5.0/apiOAuth.AssemblyInfo.cs`,
  `...MvcApplicationPartsAssemblyInfo.cs`, `...AssemblyAttributes.cs`).
- **Evidência:** `git ls-files | grep '^obj/'` lista arquivos de build como `apiOAuth.AssemblyInfo.cs`.
- **Impacto:** ruído no histórico e risco de conflito com build local. Não é brecha, é higiene.
  Mesmo problema existe em `condominio_api`.
- **Mudança:** `git rm -r --cached obj bin` e comitar. O `.gitignore` já está correto — só falta
  desindexar.
- **Aceite:** `git ls-files | grep -c '^obj/'` retorna 0.
- **Verificação:**
  ```bash
  git rm -r --cached obj bin 2>/dev/null; git ls-files | grep -c '^obj/'   # 0
  ```

### DEVOPS-04 · CI: build + teste · [P2]

- **Arquivo:** novo `.github/workflows/ci.yml`
- **Evidência:** `find .github/workflows` → inexistente. Nenhum workflow no repositório.
- **Impacto:** nada impede merge com build quebrado — como o `BUG-00` demonstra, isso já aconteceu.
- **Mudança:** workflow em `on: [push, pull_request]` com: `actions/setup-dotnet` (net8.0),
  `dotnet restore`, `dotnet build --warnaserror`, `dotnet test`, e
  `dotnet list package --vulnerable --fail-build-on-warn` como barreira.
- **Aceite:** qualquer PR que quebre o build ou reintroduza CVE é bloqueado.
- **Verificação:**
  ```bash
  # local, antes de push
  dotnet build --warnaserror && dotnet test
  ```

### DEVOPS-05 · Falta `.env.example` · [P2]

- **Arquivo:** novo `.env.example` (o `.gitignore:12` já ignora `.env`)
- **Evidência:** o `.gitignore` cobre `.env`, mas **não existe** arquivo de exemplo — quem clona o
  repositório não descobre o nome da variável que `SEC-01` introduziu.
- **Impacto:** sem exemplo, a única forma de descobrir a variável é ler `Settings.cs`. Como
  `SEC-01` faz a API **não iniciar** sem ela, um desenvolvedor novo simplesmente não roda o projeto.
- **Mudança:**
  ```
  # API de autenticação — copiar para .env e preencher
  # Mínimo 32 bytes. Gere com: openssl rand -hex 32
  API_AUTHENTICATION_JWT_SECRET=
  ```
- **Aceite:** `.env.example` existe no git e `.env` continua ignorado.
- **Verificação:**
  ```bash
  ls .env.example && git check-ignore -q .env && echo "OK: .env ignorado"
  ```

---

## 7. Documentação

### DOC-01 · README não documenta as variáveis de ambiente · [P2]

- **Arquivo:** `README.md` (102 linhas)
- **Evidência:** o README cobre instalação/execução, mas após `SEC-01` a API **não sobe** sem
  `API_AUTHENTICATION_JWT_SECRET`. O README continuaria dando instruções que falham.
- **Impacto:** documentação que ensina a rodar um serviço que não inicia é pior que ausência de
  documentação — o desenvolvedor perde tempo achando que a máquina está quebrada.
- **Mudança:** (1) seção "Variáveis de ambiente" com a tabela de `DEVOPS-05`; (2) exemplo de login
  com `curl` (a rota que `BUG-01` cria); (3) **corrigir a afirmação de que a API está pronta** —
  enquanto `BUG-01` não existir, o login não funciona.
- **Aceite:** seguir o README em máquina limpa leva a uma API funcional que autentica.
- **Verificação:** seguir o README do zero → login retorna `200`.

### DOC-02 · Falta `SECURITY.md` · [P3]

- **Arquivo:** novo `SECURITY.md`
- **Evidência:** o repositório tem `LICENSE`, mas nenhum guia de reporte de vulnerabilidade.
- **Impacto:** sem canal publicado, um achado de segurança (como a chave exposta em `SEC-01`) não
  tem para onde ser reportado. Falta também o registro das decisões de ameaça já tomadas —
  a fronteira de tenant pela claim `database` está apenas implícita no código.
- **Mudança:** criar com: fluxo de reporte, threat model resumido (forja de token por chave fraca,
  brute-force, BOLA entre tenants) e a matriz da claim `database` como fronteira de tenant.
- **Aceite:** arquivo existe e cita o canal de reporte.
- **Verificação:** `ls SECURITY.md`

---

## 8. Ordem de execução (waves)

### Wave 1 — Destravamento e parada do vazamento (P0)
1. **`BUG-00`** — trocar `&` por `&&`. Sem isso nada mais é verificável.
2. **`SEC-01`** — remover a chave do código **e rotacionar**. Maior impacto isolado.
3. **`SEC-08`** — remover `UserRepository` (bypass de senha).
4. **`BUG-01`** — criar a rota de login ligada ao serviço real.
5. **`BUG-02`** — `FirstOrDefault` em vez de `ToList()[0]`.

> Após a Wave 1 a API está utilizável e não é trivialmente quebrável.
> A rotação da chave depende de **ação sua**, não da IA (ver §9).

### Wave 2 — Blindagem do caminho de login (P1)
6. **`BUG-05`** — isolamento de tenant (o mais grave dos restantes).
7. **`SEC-03`** — bcrypt com marcador de versão + migração dos hashes SHA-256 existentes.
8. **`SEC-02`** — extração segura do header Bearer.
9. **`SEC-04`** — rate limit.
10. **`BUG-03`** — `catch` específico + logging real.
11. **`TEST-01`** e **`TEST-02`** — trava de regressão do que já foi corrigido.

### Wave 3 — Plataforma e ciclo de vida (P1/P2)
12. **`SEC-05`**, **`SEC-06`**, **`SEC-07`** — endurecimento do JWT e do transporte.
13. **`DEVOPS-01`** → **`DEVOPS-03`** — net8.0 e CVE zero (habilita os anteriores no build).
14. **`IMP-01`** a **`IMP-04`** — jti, refresh, resposta uniforme, tipos explícitos.

### Wave 4 — Higiene e documentação (P2/P3)
15. **`BUG-04`**, **`DEVOPS-02`**, **`DEVOPS-04`**, **`DEVOPS-05`**, **`DOC-01`**, **`DOC-02`**.

**Dependências que não podem ser invertidas:**
`BUG-00` antes de tudo (sem build, nada é verificável) · `SEC-03` antes de `SEC-04` (rate limit só
faz sentido com bcrypt caro) · `SEC-08` antes de `BUG-01` (o bloco comentado é o único caller de
`UserRepository`) · `DEVOPS-01` antes de `DEVOPS-03`.

---

## 9. Fora de escopo / riscos

| Item | Decisão | Motivo |
|---|---|---|
| Trocar JWT por sessão com cookie | **Não** | O `JwtBearer` já está correto. Reescrever auth é risco sem ganho. |
| Migrar Mongo → EF Core / SQL | **Não** | Fora do escopo. O modelo multi-tenant por database é adequado. |
| `CondominioController` / `CondominioSite` | **Não** | Não analisados em detalhe; abrir item próprio sob demanda. |
| `neo_app`, `whatssap_vendas` | **Não** | Vivem em outros repositórios; ver `PLANO_MELHORIAS_MASTER.md`. |

**Riscos desta execução:**

- **`SEC-01` exige ação sua.** A IA remove o literal do código; **só você** rotaciona a chave no
  servidor e reescreve o histórico. Sem isso o item fica incompleto.
- **`SEC-03` invalida senhas existentes** se a migração não for feita. Use o marcador `alg` e
  re-hashear no primeiro login — **nunca** troque o verificador direto.
- **Forçar net8.0 (`DEVOPS-01`) pode quebrar o build** por mudança de API em `JwtBearer`. Valide
  local antes de comitar; o fallback é permanecer no .NET 5 **apenas** até os CVE saírem.
- **`BUG-01` remove o caller de `UserRepository`**, por isso a ordem `SEC-08` → `BUG-01` importa:
  apagar o arquivo antes deixaria referência órfã e quebraria o build.

---

## 10. Definição de pronto (DoD)

**Segurança**
- [ ] `SEC-01` — nenhum literal de chave; variável obrigatória; **chave rotacionada**
- [ ] `SEC-08` — `UserRepository` removido; `== x.Password` inexistente
- [ ] `SEC-03` — senhas em bcrypt ≥ 12; migração dos legados funciona
- [ ] `SEC-02` — sem header ⇒ `401`, nunca `500`
- [ ] `SEC-04` — 6ª tentativa ⇒ `429` com `Retry-After`
- [ ] `SEC-05` — token sem `iss`/`aud` rejeitado
- [ ] `SEC-06` — segredo < 32 bytes recusa a inicialização
- [ ] `SEC-07` — HSTS ativo em produção; sem loop atrás de proxy

**Funcional**
- [ ] `BUG-00` — `dotnet build` com 0 erros
- [ ] `BUG-01` — `POST /v1/account/login` funciona
- [ ] `BUG-02` — usuário inexistente ⇒ `401` sem exceção
- [ ] `BUG-03` — falha real vira log + status correto
- [ ] `BUG-04` — cadastro é atômico
- [ ] `BUG-05` — tenant de outro condomínio ⇒ `401`

**Testes e qualidade**
- [ ] `TEST-01` — ≥ 6 testes do token, todos passando
- [ ] `TEST-02` — login coberto de ponta a ponta
- [ ] `IMP-01`/`IMP-02`/`IMP-03`/`IMP-04` concluídos

**Infra**
- [ ] `DEVOPS-01` — alvo `net8.0`
- [ ] `DEVOPS-03` — `dotnet list package --vulnerable` vazio
- [ ] `DEVOPS-02` — `obj/` fora do índice
- [ ] `DEVOPS-04` — CI verde e obrigatório
- [ ] `DEVOPS-05` — `.env.example` no repositório

**Documentação**
- [ ] `DOC-01` — README descreve o estado real e as variáveis
- [ ] `DOC-02` — `SECURITY.md` existe

**Validação final:**
```bash
dotnet build --warnaserror && dotnet test && dotnet list package --vulnerable
```

---

*Fim do plano. Gerado por leitura direta do código em 2026-10-02. Nenhum item aqui já estava
corrigido — todos apontam para defeitos ainda presentes.*
