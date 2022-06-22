using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using api_authentication.Models;
using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System.Linq;
using api_authentication.Services;
using api_authentication.Repositories;

namespace api_authentication.Controllers
{
    [Route("v1/account")]
    public class UserController : ControllerBase
    {
        CondominioService _service;
        public UserController(CondominioService cond) => _service = cond;
        /*
        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public async Task<ActionResult<dynamic>> Authenticate([FromForm]UserCondominio model)
        {
            var user =  UserRepository.Get(model.Username, model.Password);

            if (user == null)
                return NotFound(new { message = "Usuário ou senha inválidos" });

            var token = TokenService.GenerateToken(user);
            user.Password = "";
            return new
            {
                user = user,
                token = token
            };
        }
        */
        [HttpGet]
        [Route("anonymous")]
        [AllowAnonymous]
        public string Anonymous() => "Anônimo";

        [HttpGet]
        [Route("authenticated")]
        [Authorize]
        public string Authenticated() => String.Format("Autenticado - {0}", User.Identity.Name);

        [HttpGet]
        [Route("employee")]
        [Authorize(Roles = "employee,manager")]
        public string Employee() => "Funcionário";

        [HttpGet]
        [Route("manager")]
        [Authorize(Roles = "manager")]
        [AutoValidateAntiforgeryToken]
        public dynamic Manager() {
            bool isValid = _service.tokenAuthorization(Request);
            if(isValid) {
                return Ok();
            } else {
                return Unauthorized();
            }
        }

    }
}