using System.ComponentModel.DataAnnotations;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace apiOAuth.Models
{
    public class UserCondominio
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string id {get; set;}
        [Required]
        public string username {get; set;}
        [Required]
        public string password {get; set;}
        [Required]
        public string nameCondominio {get; set;}
        [Required]
        public string email {get; set;}
        public string role {get; set;}
    }
}