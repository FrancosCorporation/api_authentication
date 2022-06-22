using apiOAuth.Models;
using MongoDB.Driver;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using MongoDB.Bson;
using System;
using Microsoft.AspNetCore.Http;
using apiOAuth.Services;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;

namespace apiOAuth.Services
{
    public class CondominioService : ControllerBase
    {
        private readonly IMongoDatabase _condominiosDatabase;
        private readonly MongoClient _clientMongoDb;

        public CondominioService(ICondominioDatabaseSetting setting)
        {
            var client = new MongoClient(setting.ConnectionString);
            _clientMongoDb = client;
            _condominiosDatabase = client.GetDatabase(setting.DatabaseName);
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

        public string RegisterUserAndCreateDatabase(string username, string password, string nameCondominio, string email)
        {
            try
            {
                string _passwordSHA256 = passToHash(password: password);
                IMongoDatabase _newDatabase = _clientMongoDb.GetDatabase(nameCondominio);
                _newDatabase.CreateCollection("users");
                _newDatabase.CreateCollection("config_app");
                _newDatabase.CreateCollection("academia");
                _newDatabase.CreateCollection("avisos");

                _newDatabase.GetCollection<BsonDocument>("users").InsertOne(new BsonDocument{
                    {"_id", ObjectId.GenerateNewId()},
                    {"username", username.ToLower()},
                    {"password", _passwordSHA256},
                    {"nameCondominio", nameCondominio},
                    {"role", "Administrator"},
                    {"e-mail", email},
                    {"data-create", DateTime.Now}
                });

                return "Condominio "+nameCondominio+" cadastrado com sucesso!";
            }
            catch (System.Exception)
            {
                return "Não foi possivel realizar o cadastro, tente novamente mais tarde.";
            }
            
        }

        public dynamic loginCondominio(UserCondominio user)
        {
            try {
                string _passwordSHA256 = passToHash(user.password);

                IMongoDatabase _newDatabase = _clientMongoDb.GetDatabase(user.nameCondominio);
                IMongoCollection<UserCondominio> _users = _newDatabase.GetCollection<UserCondominio>("users");
                UserCondominio _user = _users.Find(_user => _user.username == user.username & _user.password == _passwordSHA256).ToList()[0];
                string _tokenUser = TokenService.GenerateToken(_user);

                return Ok(new {token = _tokenUser});

            } catch(SystemException e)
            {
                Console.Write(e);
                return Unauthorized();
            }
            
        }

        public dynamic myUser(HttpRequest request) {
            
            if(TokenService.ValidateToken(request))
            {
                JObject jsonClaim = TokenService.UnGenereteToken(request);
                IMongoDatabase _newDatabase = _clientMongoDb.GetDatabase(jsonClaim["database"].ToString());
                IMongoCollection<UserCondominio> _users = _newDatabase.GetCollection<UserCondominio>("users");
                UserCondominio _user = _users.Find(_user => _user.id == jsonClaim["objectId"].ToString()).ToList()[0];
                _user.password = "Não veja";
                return Ok(_user);
            } else 
            {
                return Unauthorized("Token Inválido");
            }
        }

        public string passToHash(string password) {
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

        public dynamic GetCondominios(string nameCollection)
        {
            List<User> _usersCollection = new List<User>();
            IMongoCollection<Users> _users = _condominiosDatabase.GetCollection<Users>(nameCollection);
            List<Users> _user =  _users.Find(user => true).ToList();
            //_user[0].users["users"][0]; //Matheus
            try
            {
                foreach(Dictionary<string, dynamic> u in _user[0].users["users"])
                {
                    _usersCollection.Add(new User {Username = u["Username"], Password = u["Password"], Role = u["Role"]});
                }
                return _usersCollection;
            }
            catch (System.Exception)
            {
                return "Condominio não encontrado.";
            }
            
        }
        
        public dynamic nameDatabase() => _condominiosDatabase.DatabaseNamespace;

        public dynamic tokenAuthorization(HttpRequest request) {
            //Console.Write(httpRequest.Headers["Authorization"].ToString().Split(" ")[1]);
            TokenService.ValidateToken(request);
            return TokenService.ValidateToken(request);;
        }

    }
}