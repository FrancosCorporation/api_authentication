using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using api_authentication.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using Microsoft.IdentityModel.Tokens;

namespace api_authentication.Services
{
    public sealed class TokenResponse
    {
        public string token { get; set; }
        public DateTime expiresAtUtc { get; set; }
    }

    public sealed class TokenValidationResult
    {
        public ClaimsPrincipal Principal { get; set; }
        public string TokenId { get; set; }
        public DateTime ExpiresAtUtc { get; set; }
    }

    public static class TokenService
    {
        private static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        static TokenService() => Handler.MapInboundClaims = false;

        public static TokenResponse GenerateToken(UserCondominio user)
        {
            var now = DateTime.UtcNow;
            var expiresAt = now.AddMinutes(15);
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("objectId", user.id),
                    new Claim(ClaimTypes.Name, user.username),
                    new Claim("database", user.nameCondominio),
                    new Claim(ClaimTypes.Role, user.role),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
                }),
                Issuer = Settings.JwtIssuer,
                Audience = Settings.JwtAudience,
                IssuedAt = now,
                NotBefore = now,
                Expires = expiresAt,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Settings.GetJwtSecretBytes()),
                    SecurityAlgorithms.HmacSha256)
            };

            return new TokenResponse
            {
                token = Handler.WriteToken(Handler.CreateToken(descriptor)),
                expiresAtUtc = expiresAt
            };
        }

        public static TokenValidationResult ValidateToken(HttpRequest request)
        {
            if (!TryGetBearerToken(request, out var token)) return null;

            try
            {
                var principal = Handler.ValidateToken(token, CreateValidationParameters(), out var validatedToken);
                if (!(validatedToken is JwtSecurityToken jwt) ||
                    !string.Equals(jwt.Header.Alg, SecurityAlgorithms.HmacSha256, StringComparison.Ordinal))
                    return null;

                var tokenId = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
                if (string.IsNullOrWhiteSpace(tokenId)) return null;

                return new TokenValidationResult
                {
                    Principal = principal,
                    TokenId = tokenId,
                    ExpiresAtUtc = jwt.ValidTo
                };
            }
            catch (SecurityTokenException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        public static TokenValidationParameters CreateValidationParameters(byte[] signingKey = null)
        {
            signingKey = signingKey ?? Settings.GetJwtSecretBytes();
            return new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(signingKey),
                ValidateIssuer = true,
                ValidIssuer = Settings.JwtIssuer,
                ValidateAudience = true,
                ValidAudience = Settings.JwtAudience,
                ValidateLifetime = true,
                NameClaimType = "name",
                RoleClaimType = "role",
                ClockSkew = TimeSpan.FromSeconds(30)
            };
        }

        public static bool TryGetBearerToken(HttpRequest request, out string token)
        {
            token = null;
            if (!System.Net.Http.Headers.AuthenticationHeaderValue.TryParse(
                    request.Headers[HeaderNames.Authorization], out var header) ||
                !string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(header.Parameter))
                return false;

            token = header.Parameter.Trim();
            return token.Length > 0;
        }
    }
}
