namespace api_authentication
{
    public static class Settings
    {
        public const string JwtSecretVariable = "API_AUTHENTICATION_JWT_SECRET";
        public const string JwtIssuer = "api_authentication";
        public const string JwtAudience = "condominio_api";

        public static byte[] GetJwtSecretBytes()
        {
            var secret = System.Environment.GetEnvironmentVariable(JwtSecretVariable);
            if (string.IsNullOrWhiteSpace(secret))
                throw new System.InvalidOperationException(
                    $"{JwtSecretVariable} ausente. Defina um segredo aleatório com pelo menos 32 bytes.");

            var bytes = System.Text.Encoding.UTF8.GetBytes(secret);
            if (bytes.Length < 32)
                throw new System.InvalidOperationException(
                    $"{JwtSecretVariable} precisa ter pelo menos 32 bytes UTF-8; recebeu {bytes.Length}.");

            return bytes;
        }
    }
}
