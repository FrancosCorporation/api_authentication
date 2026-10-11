using System.Threading.Tasks;
using api_authentication.Models;
using api_authentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace api_authentication.Controllers
{
    [ApiController]
    [Route("v1/account")]
    public class UserController : ControllerBase
    {
        private readonly CondominioService _service;

        public UserController(CondominioService service) => _service = service;

        [HttpPost("login")]
        [AllowAnonymous]
        [EnableRateLimiting("login")]
        public Task<IActionResult> Login([FromBody] LoginRequest model) =>
            _service.loginCondominio(model, HttpContext.Connection.RemoteIpAddress?.ToString(), Response);

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var token = TokenService.ValidateToken(Request);
            if (token == null) return Unauthorized();

            await _service.RevokeToken(token.TokenId, token.ExpiresAtUtc);
            return NoContent();
        }

        [HttpGet("anonymous")]
        [AllowAnonymous]
        public ActionResult<string> Anonymous() => "Anônimo";

        [HttpGet("authenticated")]
        [Authorize]
        public ActionResult<string> Authenticated() => $"Autenticado - {User.Identity?.Name}";

        [HttpGet("employee")]
        [Authorize(Roles = "employee,manager,Administrator")]
        public ActionResult<string> Employee() => "Funcionário";

        [HttpGet("manager")]
        [Authorize(Roles = "manager,Administrator")]
        public IActionResult Manager() => Ok();
    }
}
