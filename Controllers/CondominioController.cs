using System.Threading.Tasks;
using System.Collections.Generic;
using api_authentication.Models;
using api_authentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace api_authentication.Controllers
{
    [Route("api")]
    [ApiController]
    public class CondominioController : ControllerBase
    {
        private readonly CondominioService _condominioService;

        public CondominioController(CondominioService condominioService) => _condominioService = condominioService;

        [HttpGet("listcollection")]
        [Authorize(Roles = "Administrator")]
        public ActionResult<IReadOnlyList<string>> ListCollections() => _condominioService.GetListNameCollections();

        [HttpGet("databasename")]
        [Authorize(Roles = "Administrator")]
        public ActionResult<string> DatabaseName() => _condominioService.nameDatabase();

        // Esta rota antiga devolvia registros de usuário, inclusive hashes de senha.
        // A coleção central não tem escopo de tenant, então o endpoint foi removido.
        [HttpGet("usercollection")]
        public IActionResult UserCollection() => NotFound();

        [HttpGet("databases")]
        [Authorize(Roles = "Administrator")]
        public ActionResult<IReadOnlyList<string>> DatabasesName()
        {
            var tenant = User.FindFirst("database")?.Value;
            return string.IsNullOrWhiteSpace(tenant)
                ? Forbid()
                : new[] { tenant };
        }

        [HttpPost("RegisterUserAndCondominio")]
        [AllowAnonymous]
        [EnableRateLimiting("registration")]
        public Task<IActionResult> RegisterUserAndCondominio(
            [FromForm] string username,
            [FromForm] string password,
            [FromForm] string nameCondominio,
            [FromForm] string email) =>
            _condominioService.RegisterUserAndCreateDatabase(username, password, nameCondominio, email);

        [HttpPost("LoginCondominio")]
        [AllowAnonymous]
        [EnableRateLimiting("login")]
        public Task<IActionResult> LoginCondominio([FromForm] UserCondominio user) =>
            _condominioService.loginCondominio(new LoginRequest
            {
                username = user?.username,
                password = user?.password,
                nameCondominio = user?.nameCondominio
            }, HttpContext.Connection.RemoteIpAddress?.ToString(), Response);

        [HttpGet("myUser")]
        [Authorize(Roles = "Administrator")]
        public Task<IActionResult> myUser() => _condominioService.myUser(User);
    }
}
