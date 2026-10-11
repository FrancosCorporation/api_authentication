using System.ComponentModel.DataAnnotations;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace api_authentication.Models
{
    public class UserCondominio
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string id {get; set;}
        [Required, StringLength(64, MinimumLength = 1)]
        [BsonElement("username")]
        public string username {get; set;}
        [Required, StringLength(72, MinimumLength = 1)]
        [BsonElement("password")]
        public string password {get; set;}
        [Required, StringLength(63, MinimumLength = 2)]
        [BsonElement("nameCondominio")]
        public string nameCondominio {get; set;}
        [BsonElement("e-mail")]
        public string email {get; set;}
        [BsonElement("alg")]
        public string passwordAlgorithm {get; set;}
        [BsonElement("role")]
        public string role {get; set;}
    }
}
