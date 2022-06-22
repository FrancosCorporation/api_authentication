using System.Collections.Generic;
using System.Linq;
using apiOAuth.Models;

namespace apiOAuth.Repositories
{
    public static class UserRepository
    {
        public static User Get(string username, string password)
        {
            var users = new List<User>();
            users.Add(new User { Username = "batman", Password = "batman", Role = "manager" });
            users.Add(new User { Username = "robin", Password = "robin", Role = "employee" });
            return users.Where(x => x.Username.ToLower() == username.ToLower() && x.Password == x.Password).FirstOrDefault();
        }
    }
}