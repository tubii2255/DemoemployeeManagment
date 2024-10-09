using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(IUserAccount accountInterface) : ControllerBase
    {
        [HttpPost("register")]

        public async Task<IActionResult> CreateAsync(Register User)
        {
            if (User == null) return BadRequest("Models is empty");
            var result = await accountInterface.CreateAsync(User);
            return Ok(result);
        }
        [HttpPost("login")]
        public async Task<IActionResult> SignInAsync(Login user)
        {
            if (user == null) return BadRequest("Model is empty");
            var result = await accountInterface.SignInAsync(user);
            return Ok(result);

        }
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshTokenAsync(RefreshToken token)
        {
            if (token == null) return BadRequest("model is empty");
            var result = await accountInterface.RefreshTokenAsync(token);
            return Ok(result);
        }
    }

}
