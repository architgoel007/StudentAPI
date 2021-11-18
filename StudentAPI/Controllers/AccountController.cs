using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using StudentAPI.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace StudentAPI.Controllers
{
    [Route("controller")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(Login loginModel)
        {
            var user = await userManager.FindByNameAsync(loginModel.UserName);
            if (user != null && await userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
                var Token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT: ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
                    );
                CustomResponse customResponse = new CustomResponse();
                customResponse.Token = new JwtSecurityTokenHandler().WriteToken(Token);
                customResponse.expiration = Token.ValidTo;
                return Ok(customResponse);
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterAdmin(Register registerModel)
        {
            var userExists = await userManager.FindByNameAsync(registerModel.UserName);
            if (userExists != null)
            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Already Exists" });

            IdentityUser user = new IdentityUser()
            {
                Email = registerModel.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerModel.UserName
            };

            var result = await userManager.CreateAsync(user, registerModel.Password);
            if(!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation Failed" });

            if (!await roleManager.RoleExistsAsync(ApplicationUserRoles.Admin))
                await roleManager.CreateAsync(new IdentityRole(ApplicationUserRoles.Admin));
            if (!await roleManager.RoleExistsAsync(ApplicationUserRoles.Admin))
                await roleManager.CreateAsync(new IdentityRole(ApplicationUserRoles.User));

            if(!string.IsNullOrEmpty(registerModel.Role) && registerModel.Role==ApplicationUserRoles.Admin)
            {
                await userManager.AddToRoleAsync(user, ApplicationUserRoles.Admin);
            }
            else
            {
                await userManager.AddToRoleAsync(user, ApplicationUserRoles.User);
            }
            return Ok(new Response { Status = "Success", Message = "User Created Successfully" });
        }
    }

}
