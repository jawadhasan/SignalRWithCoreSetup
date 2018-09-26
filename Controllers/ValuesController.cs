using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AsyncApi.Controllers
{
    [Produces("application/json")]
    [Route("api/Values")]
    [Authorize]
    public class ValuesController : Controller
    {
        [HttpGet]
        public IActionResult Get()
        {
            var utcTime = $"Utc-Time at Server: {DateTime.UtcNow}";
            return Ok(utcTime);
        }
    }
}