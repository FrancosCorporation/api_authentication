using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using apiOAuth.Models;
using System;
using Microsoft.AspNetCore.Authorization;
using System.Linq;
using apiOAuth.Services;

namespace apiOAuth.Controllers
{
    [Route("api")]
    [ApiController]
    public class CondominioController : ControllerBase
    {
        private readonly CondominioService _condominioService;
        public CondominioController(CondominioService condominioService)
        {
            _condominioService = condominioService;
        }

        [HttpGet("listcollection")]
        public ActionResult<dynamic> ListCollections() => _condominioService.GetListNameCollections();

        [HttpGet("databasename")]
        public ActionResult<dynamic> DatabaseName() => _condominioService.nameDatabase();

        [HttpGet("usercollection")]
        public ActionResult<dynamic> UserCollection(string nameCondominio) => _condominioService.GetCondominios(nameCondominio);

        [HttpGet("databases")]
        public ActionResult<dynamic> DatabasesName() => _condominioService.GetListNameDatabase();

        [HttpPost("RegisterUserAndCondominio")]
        public ActionResult<dynamic> RegisterUserAndCondominio([FromForm]string username, [FromForm]string password, [FromForm]string nameCondominio,[FromForm]string email) => 
            _condominioService.RegisterUserAndCreateDatabase(username, password,nameCondominio,email);


        [HttpPost("LoginCondominio")]
        public ActionResult<dynamic> LoginCondominio([FromForm]UserCondominio user) => _condominioService.loginCondominio(user);

        [HttpGet("myUser")]
        [Authorize(Roles = "Administrator")]
        public ActionResult<dynamic> myUser() => _condominioService.myUser(Request);
    }
}