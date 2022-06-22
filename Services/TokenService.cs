using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using api_authentication.Models;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Http;

/*
    Gera token utilizando a chave Secret no arquivo Settings
*/
namespace api_authentication.Services
{
    public static class TokenService
    {
        public static string GenerateToken(UserCondominio user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Settings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("objectId", user.id.ToString()),
                    new Claim(ClaimTypes.Name, user.username.ToString()),
                    new Claim("database", user.nameCondominio.ToString()),
                    new Claim(ClaimTypes.Role, user.role.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(10),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static dynamic ValidateToken(HttpRequest request)
        {
            string jwtString = request.Headers["Authorization"].ToString().Split(" ")[1];
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;
            TokenValidationParameters validationParameters = new TokenValidationParameters()
            {
                ValidateLifetime = true, // Because there is no expiration in the generated token
                ValidateAudience = false, // Because there is no audiance in the generated token
                ValidateIssuer = false,   // Because there is no issuer in the generated token
                ValidIssuer = "Sample",
                ValidAudience = "Sample",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Settings.Secret)), // The same key as the one that generate the token
                LifetimeValidator = (DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                {
                    if (expires != null)
                    {
                        if (DateTime.Now < expires.Value.ToLocalTime()) return true;
                    }
                    return false;
                }
            };

            try
            {
                var p = tokenHandler.ValidateToken(jwtString, validationParameters, out validatedToken);
                return true;
            }
            catch (SecurityTokenException e)
            {
                return false;
            }
            
        }

        public static dynamic UnGenereteToken(HttpRequest request)
        {
            string jwtString = request.Headers["Authorization"].ToString().Split(" ")[1];
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jsonToken = handler.ReadJwtToken(jwtString);
            JObject jsonClaim = JObject.Parse(jsonToken.ToString().Split(".")[1]);
            return jsonClaim;
        }

    }
}