using EcommAPI.Helper;
using EcommAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.DotNet.Scaffolding.Shared.Messaging;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.RegularExpressions;

namespace EcommAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly DBContext _dBContext;

        public UsersController(DBContext dBContext)
        {
            _dBContext = dBContext;
        }

        [HttpPost("login")]

        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }

            

            var user = await _dBContext.Users.FirstOrDefaultAsync(u => 
            u.Username == userObj.Username && u.Password == userObj.Password);

            if(user == null)
            {
                return NotFound(new {Message = "User Not Found" });
            }
            return Ok(new { Message = " User Login Sucessfully! "});
        }

        [HttpPost("register")]

        public async Task<IActionResult> RegisterUser([FromBody] User user)
        {
            if(user == null)
            {
                return BadRequest();
            }
            var checkUsername = await UsernameCheckExitsAsync(user.Username);
            if (checkUsername)
            {
                return BadRequest(new { Message = " Username Already Exits! " });
            }

            var checkEmail = await EmailCheckExitsAsync(user.Email);
            if (checkEmail)
            {
                return BadRequest(new { Message = " Email Already Exits! " });
            }

            var pass = PasswordStrengthCheck(user.Password);
            if (!string.IsNullOrEmpty(pass))
            {
                return BadRequest(new { Message = pass.ToString() });
            }

            user.Password = PasswordHasher.HashPassword(user.Password);
            await _dBContext.Users.AddAsync(user);
            await _dBContext.SaveChangesAsync();

            return Ok(user);
        }

        private async Task<bool> UsernameCheckExitsAsync(string username)
        => await _dBContext.Users.AnyAsync(x => x.Username == username);

        private async Task<bool> EmailCheckExitsAsync(string email)
            => await _dBContext.Users.AnyAsync(x => x.Email == email);

        private string PasswordStrengthCheck(string password)
        {
            StringBuilder sb = new StringBuilder();

            if(password.Length < 8)
               sb.Append("Password cannot be less than 8 "+Environment.NewLine);
            
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
                && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be Alphanumeric "+Environment.NewLine);
            if (!Regex.IsMatch(password, "[@,#,$,%]"))
                sb.Append("Password must include special characters" + Environment.NewLine);

            return sb.ToString();
        }
    }
}
