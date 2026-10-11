using System.ComponentModel.DataAnnotations;

namespace api_authentication.Models
{
    public sealed class LoginRequest
    {
        [Required, StringLength(64, MinimumLength = 1)]
        public string username { get; set; }

        [Required, StringLength(72, MinimumLength = 1)]
        public string password { get; set; }

        [Required, StringLength(63, MinimumLength = 2)]
        public string nameCondominio { get; set; }
    }
}
