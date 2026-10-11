using api_authentication.Models;
using MongoDB.Driver;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text;
using MongoDB.Bson;
using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Threading;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace api_authentication.Services
{
    public class CondominioService
    {
        private readonly IMongoDatabase _condominiosDatabase;
        private readonly MongoClient _clientMongoDb;
        private readonly ILogger<CondominioService> _logger;
        private static readonly string DummyPasswordHash = BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString("N"), workFactor: 12);
        private static readonly ConcurrentDictionary<string, LoginFailureWindow> LoginFailures =
            new ConcurrentDictionary<string, LoginFailureWindow>();
        private static readonly SemaphoreSlim RegistrationGate = new SemaphoreSlim(1, 1);

        public CondominioService(ICondominioDatabaseSetting setting, ILogger<CondominioService> logger)
        {
            var client = new MongoClient(setting.ConnectionString);
            _clientMongoDb = client;
            _condominiosDatabase = client.GetDatabase(setting.DatabaseName);
            _logger = logger;
        }

        public List<string> GetListNameDatabase()
        {
            List<string> listNameDatabase = new List<string>();
            using (var cursor = _clientMongoDb.ListDatabaseNames())
            {
                while(cursor.MoveNext())
                {
                    foreach(var current in cursor.Current)
                    {
                        if(current != "admin" && current != "config" && current != "local") listNameDatabase.Add(current);
                    }
                }
            }

            return listNameDatabase;
        }

        public async Task<IActionResult> RegisterUserAndCreateDatabase(string username, string password, string nameCondominio, string email)
        {
            username = username?.Trim().ToLowerInvariant();
            nameCondominio = nameCondominio?.Trim().ToLowerInvariant();
            email = email?.Trim();
            if (!IsValidTenantName(nameCondominio) || string.IsNullOrWhiteSpace(username) || username.Length > 64 ||
                string.IsNullOrWhiteSpace(password) || Encoding.UTF8.GetByteCount(password) < 12 ||
                Encoding.UTF8.GetByteCount(password) > 72 || !System.Net.Mail.MailAddress.TryCreate(email, out _))
                return new BadRequestObjectResult(new { message = "Dados de cadastro inválidos." });

            await RegistrationGate.WaitAsync();
            var databaseCreated = false;
            try
            {
                if (_clientMongoDb.ListDatabaseNames().ToList().Contains(nameCondominio, StringComparer.Ordinal))
                    return new ConflictObjectResult(new { message = "Condomínio já cadastrado." });

                var _newDatabase = _clientMongoDb.GetDatabase(nameCondominio);
                await _newDatabase.CreateCollectionAsync("users");
                databaseCreated = true;
                await _newDatabase.CreateCollectionAsync("config_app");
                await _newDatabase.CreateCollectionAsync("academia");
                await _newDatabase.CreateCollectionAsync("avisos");
                var users = _newDatabase.GetCollection<BsonDocument>("users");
                var usernameIndex = new CreateIndexModel<BsonDocument>(
                    Builders<BsonDocument>.IndexKeys.Ascending("username"),
                    new CreateIndexOptions { Unique = true, Name = "uq_users_username" });
                await users.Indexes.CreateOneAsync(usernameIndex);

                await users.InsertOneAsync(new BsonDocument{
                    {"_id", ObjectId.GenerateNewId()},
                    {"username", username},
                    {"password", BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12)},
                    {"alg", "bcrypt12"},
                    {"nameCondominio", nameCondominio},
                    {"role", "Administrator"},
                    {"e-mail", email},
                    {"data-create", DateTime.UtcNow}
                });

                return new OkObjectResult(new { message = "Condomínio cadastrado com sucesso." });
            }
            catch (MongoWriteException ex) when (ex.WriteError?.Category == ServerErrorCategory.DuplicateKey)
            {
                if (databaseCreated) await TryDropDatabase(nameCondominio);
                return new ConflictObjectResult(new { message = "Condomínio ou usuário já cadastrado." });
            }
            catch (MongoException ex)
            {
                if (databaseCreated) await TryDropDatabase(nameCondominio);
                _logger.LogError(ex, "Falha MongoDB ao cadastrar condomínio {Tenant}", nameCondominio);
                return new ObjectResult(new { message = "Serviço temporariamente indisponível." })
                { StatusCode = StatusCodes.Status503ServiceUnavailable };
            }
            catch (Exception ex)
            {
                if (databaseCreated) await TryDropDatabase(nameCondominio);
                _logger.LogError(ex, "Falha inesperada ao cadastrar condomínio {Tenant}", nameCondominio);
                return new ObjectResult(new { message = "Não foi possível concluir o cadastro." })
                { StatusCode = StatusCodes.Status500InternalServerError };
            }
            finally
            {
                RegistrationGate.Release();
            }
        }

        public async Task<IActionResult> loginCondominio(LoginRequest user, string remoteIp, HttpResponse response)
        {
            var tenant = user?.nameCondominio?.Trim().ToLowerInvariant() ?? string.Empty;
            var username = user?.username?.Trim().ToLowerInvariant() ?? string.Empty;
            var password = user?.password ?? string.Empty;
            if (string.IsNullOrWhiteSpace(username) || Encoding.UTF8.GetByteCount(password) > 72)
            {
                var invalidKey = CreateLoginFailureKey(tenant, username, remoteIp);
                return await InvalidLogin(LoginFailures.GetOrAdd(invalidKey, _ => new LoginFailureWindow()), password);
            }

            var failureKey = CreateLoginFailureKey(tenant, username, remoteIp);
            var failures = LoginFailures.GetOrAdd(failureKey, _ => new LoginFailureWindow());
            if (failures.IsBlocked(DateTimeOffset.UtcNow, out var retryAfter))
            {
                response.Headers["Retry-After"] = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                return new ObjectResult(new { message = "Tente novamente mais tarde." })
                { StatusCode = StatusCodes.Status429TooManyRequests };
            }

            if (!IsValidTenantName(tenant) || new[] { "admin", "config", "local" }.Contains(tenant, StringComparer.Ordinal))
                return await InvalidLogin(failures, password);

            try
            {
                var tenantNames = _clientMongoDb.ListDatabaseNames().ToList();
                if (!tenantNames.Contains(tenant, StringComparer.Ordinal))
                    return await InvalidLogin(failures, password);

                var users = _clientMongoDb.GetDatabase(tenant).GetCollection<UserCondominio>("users");
                var storedUser = await users.Find(x => x.username == username).FirstOrDefaultAsync();
                if (storedUser == null || !string.Equals(storedUser.nameCondominio, tenant, StringComparison.Ordinal))
                    return await InvalidLogin(failures, password);

                var validPassword = false;
                if (storedUser.passwordAlgorithm == "bcrypt12")
                {
                    try { validPassword = BCrypt.Net.BCrypt.Verify(password, storedUser.password); }
                    catch (ArgumentException) { validPassword = false; }
                }
                else if (string.IsNullOrEmpty(storedUser.passwordAlgorithm) || storedUser.passwordAlgorithm == "sha256")
                {
                    var expected = Encoding.ASCII.GetBytes(passToHash(password));
                    var actual = Encoding.ASCII.GetBytes(storedUser.password ?? string.Empty);
                    validPassword = actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected);
                    BCrypt.Net.BCrypt.Verify(password, DummyPasswordHash); // equaliza o custo do caminho legado
                    if (validPassword)
                    {
                        storedUser.password = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
                        storedUser.passwordAlgorithm = "bcrypt12";
                        await users.UpdateOneAsync(
                            x => x.id == storedUser.id,
                            Builders<UserCondominio>.Update
                                .Set(x => x.password, storedUser.password)
                                .Set(x => x.passwordAlgorithm, storedUser.passwordAlgorithm));
                    }
                }

                if (!validPassword || string.IsNullOrWhiteSpace(storedUser.role) || string.IsNullOrWhiteSpace(storedUser.id))
                    return await InvalidLogin(failures, password, storedUser.passwordAlgorithm == "bcrypt12");

                failures.Clear();
                LoginFailures.TryRemove(failureKey, out _);
                var token = TokenService.GenerateToken(storedUser);
                return new OkObjectResult(token);
            }
            catch (MongoException ex)
            {
                _logger.LogError(ex, "Falha MongoDB durante autenticação do tenant {Tenant}", tenant);
                return new ObjectResult(new { message = "Serviço temporariamente indisponível." })
                { StatusCode = StatusCodes.Status503ServiceUnavailable };
            }
        }

        private static Task<IActionResult> InvalidLogin(LoginFailureWindow failures, string password, bool bcryptAlreadyChecked = false)
        {
            if (!bcryptAlreadyChecked) BCrypt.Net.BCrypt.Verify(password, DummyPasswordHash);
            failures.RecordFailure(DateTimeOffset.UtcNow);
            PruneLoginFailures();
            return Task.FromResult<IActionResult>(new UnauthorizedObjectResult(new { message = "Usuário, senha ou condomínio inválidos." }));
        }

        private static int _loginFailureCleanupCounter;

        private static void PruneLoginFailures()
        {
            if (LoginFailures.Count < 1024 || Interlocked.Increment(ref _loginFailureCleanupCounter) % 256 != 0) return;
            var now = DateTimeOffset.UtcNow;
            foreach (var entry in LoginFailures)
                if (entry.Value.IsExpired(now)) LoginFailures.TryRemove(entry.Key, out _);
        }

        public async Task<IActionResult> myUser(ClaimsPrincipal principal)
        {
            var tenant = principal?.FindFirst("database")?.Value;
            var id = principal?.FindFirst("objectId")?.Value;
            if (!IsValidTenantName(tenant) || !ObjectId.TryParse(id, out _)) return new UnauthorizedResult();

            var users = _clientMongoDb.GetDatabase(tenant).GetCollection<UserCondominio>("users");
            var user = await users.Find(x => x.id == id).FirstOrDefaultAsync();
            if (user == null) return new NotFoundResult();

            return new OkObjectResult(new
            {
                id = user.id,
                username = user.username,
                nameCondominio = user.nameCondominio,
                email = user.email,
                role = user.role
            });
        }

        public async Task<bool> IsTokenRevoked(string tokenId)
        {
            if (string.IsNullOrWhiteSpace(tokenId)) return true;
            var revoked = _condominiosDatabase.GetCollection<BsonDocument>("revoked_tokens");
            var filter = Builders<BsonDocument>.Filter.And(
                Builders<BsonDocument>.Filter.Eq("_id", tokenId),
                Builders<BsonDocument>.Filter.Gt("expiresAtUtc", DateTime.UtcNow));
            return await revoked.Find(filter).AnyAsync();
        }

        public async Task RevokeToken(string tokenId, DateTime expiresAtUtc)
        {
            var revoked = _condominiosDatabase.GetCollection<BsonDocument>("revoked_tokens");
            await revoked.DeleteManyAsync(Builders<BsonDocument>.Filter.Lte("expiresAtUtc", DateTime.UtcNow));
            await revoked.ReplaceOneAsync(
                Builders<BsonDocument>.Filter.Eq("_id", tokenId),
                new BsonDocument { { "_id", tokenId }, { "expiresAtUtc", expiresAtUtc } },
                new ReplaceOptions { IsUpsert = true });
        }

        private static bool IsValidTenantName(string tenant)
        {
            return !string.IsNullOrWhiteSpace(tenant) && Regex.IsMatch(tenant, "^[a-z0-9][a-z0-9_-]{1,62}$");
        }

        private static string CreateLoginFailureKey(string tenant, string username, string remoteIp)
        {
            var raw = $"{tenant}\n{username}\n{remoteIp ?? "unknown"}";
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
        }

        private static string passToHash(string password)
        {
            using (SHA256 sHA256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
                byte[] passwordSha256Bytes = sHA256.ComputeHash(passwordBytes);
                StringBuilder sbSHA256 = new StringBuilder();
                for (int i = 0; i < passwordSha256Bytes.Length; i++)
                {
                    sbSHA256.Append(passwordSha256Bytes[i].ToString("X2"));
                }
                return sbSHA256.ToString();
            }
        }

        private sealed class LoginFailureWindow
        {
            private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
            private readonly Queue<DateTimeOffset> _failures = new Queue<DateTimeOffset>();

            public bool IsBlocked(DateTimeOffset now, out TimeSpan retryAfter)
            {
                lock (_failures)
                {
                    RemoveExpired(now);
                    retryAfter = _failures.Count >= 5 ? Window - (now - _failures.Peek()) : TimeSpan.Zero;
                    return _failures.Count >= 5;
                }
            }

            public void RecordFailure(DateTimeOffset now)
            {
                lock (_failures)
                {
                    RemoveExpired(now);
                    _failures.Enqueue(now);
                }
            }

            public void Clear()
            {
                lock (_failures) _failures.Clear();
            }

            public bool IsExpired(DateTimeOffset now)
            {
                lock (_failures)
                {
                    RemoveExpired(now);
                    return _failures.Count == 0;
                }
            }

            private void RemoveExpired(DateTimeOffset now)
            {
                while (_failures.Count > 0 && now - _failures.Peek() >= Window) _failures.Dequeue();
            }
        }

        public List<string> GetListNameCollections() 
        {
            List<string> listNameCollection = new List<string>();

            using (var cursor = _condominiosDatabase.ListCollectionNames())
            {
                while (cursor.MoveNext())
                {
                    foreach (var current in cursor.Current)
                    {
                        listNameCollection.Add(current);
                    }
                }
            }

            return listNameCollection;
        }

        public string nameDatabase() => _condominiosDatabase.DatabaseNamespace.DatabaseName;

        private async Task TryDropDatabase(string tenant)
        {
            try
            {
                if (IsValidTenantName(tenant)) await _clientMongoDb.DropDatabaseAsync(tenant);
            }
            catch (MongoException cleanupException)
            {
                _logger.LogError(cleanupException, "Não foi possível reverter o banco incompleto {Tenant}", tenant);
            }
        }

    }
}
