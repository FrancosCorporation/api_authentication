using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.ComponentModel.DataAnnotations;

namespace api_authentication.Models
{
    public class User
    {
        public string Username {get; set;}
        public string Password {get; set;}
        public string Role {get; set;}
    }
    
}