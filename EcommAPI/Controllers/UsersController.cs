using EcommAPI.DTO;
using EcommAPI.Helper;
using EcommAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.DotNet.Scaffolding.Shared.Messaging;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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
            u.Username == userObj.Username);

            if(user == null)
            {
                return NotFound(new {Message = "Username Not Found" });
            }

            if(!(PasswordHasher.VerifyPassword(userObj.Password, user.Password)))
            {
                return BadRequest(new { Message = "Password Not Match!" });
            }

            user.Token = GenerateJWt(user);
            var newAcessToken = user.Token;
            var newRefreshToken = GenerateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.ExpiryTime = DateTime.Now.AddDays(5);

            await _dBContext.SaveChangesAsync();

            return Ok(new TokenApiDTO
            {
                AcessToken = newAcessToken,
                RefreshToken = newRefreshToken
            });
            //return Ok(new { Token = user.Token, Message = " User Login Sucessfully! "});
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

        [Authorize(Roles="string")]
        [HttpGet("GetAllUsers")]

        public async Task<ActionResult<User>> GetUser()
        {
            var user = await _dBContext.Users.ToListAsync();
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

        private string GenerateJWt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("My12Secret34Key78sdfjsefjskjksdhfsfujgtehnsgwoiuqhnbhsu");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("role", user.Role)
                /*$"{user.fname} {user.lname}"*/
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddMinutes(10),
                SigningCredentials = credentials
            };
            var tokenObj = jwtTokenHandler.CreateToken(tokenDescriptor);

            var token = jwtTokenHandler.WriteToken(tokenObj);

            return token;

        }

        private string GenerateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenInUser = _dBContext.Users.Any(x=>x.RefreshToken == refreshToken);

            if(tokenInUser)
            {
                return GenerateRefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipalFromExpireToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("My12Secret34Key78sdfjsefjskjksdhfsfujgtehnsgwoiuqhnbhsu");
            var tokenValidationParameters = new TokenValidationParameters
            {

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if(jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid Token");

            return principal;
        }

        [HttpPost("refresh")]

        public async Task<IActionResult> RefreshToken(TokenApiDTO tokenApiDTO)
        {
            if (tokenApiDTO == null)
                return BadRequest("Invalid Client Request");

            string accessToken = tokenApiDTO.AcessToken;
            string refreshToken = tokenApiDTO.RefreshToken;

            var principal = GetPrincipalFromExpireToken(accessToken);

            var username = principal.Identity.Name;
            var user = await _dBContext.Users.FirstOrDefaultAsync(u => u.Username == username);

            if(user == null || user.RefreshToken!= refreshToken || user.ExpiryTime <= DateTime.Now)
                return BadRequest("Invalid Request");

            var newAcessToken = GenerateJWt(user);
            var newRefreshToken = GenerateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _dBContext.SaveChangesAsync();
            return Ok(new TokenApiDTO
            {
                AcessToken = newAcessToken,
                RefreshToken = newRefreshToken,
            });
        }
    }
}
