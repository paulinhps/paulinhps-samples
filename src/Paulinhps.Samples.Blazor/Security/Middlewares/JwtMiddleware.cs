using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Paulinhps.Samples.Blazor.Data;

namespace Paulinhps.Samples.Blazor.Security.Middlewares
{

    public class CustomSignInManager : SignInManager<ApplicationUser>
    {
        private const string TokenClaimName = "jwt";
        private readonly ITokenGenerator _tokenGenerator;

        public CustomSignInManager(UserManager<ApplicationUser> userManager, IHttpContextAccessor contextAccessor, IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor, ILogger<SignInManager<ApplicationUser>> logger, IAuthenticationSchemeProvider schemes, IUserConfirmation<ApplicationUser> confirmation, ITokenGenerator tokenGenerator) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
        {
            _tokenGenerator = tokenGenerator;
        }

        public override async Task SignInAsync(ApplicationUser user, bool isPersistent, string? authenticationMethod = null)
        {

            _ = await CreateUserPrincipalAsync(user);

            // Chama o método padrão para concluir o processo de autenticação
            await base.SignInAsync(user, isPersistent, authenticationMethod);
        }

        public override async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            // Verifica as credenciais do usuário
            var user = await UserManager.FindByNameAsync(userName);
            if (user == null || !await UserManager.CheckPasswordAsync(user, password))
            {
                return SignInResult.Failed;
            }

            // Chama o método base para lidar com lockouts e outros comportamentos padrão
            var result = await base.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);

            if (result.Succeeded)
            {
                await SignInAsync(user, isPersistent);
            }

            return result;
        }

         public override async Task<ClaimsPrincipal> CreateUserPrincipalAsync(ApplicationUser user)
    {
        // Obtenha o principal padrão
        var principal = await base.CreateUserPrincipalAsync(user);
        var identity = (ClaimsIdentity)principal.Identity!;

        // Gere o token JWT
        var token = _tokenGenerator.GenerateToken(principal);


        if(!string.IsNullOrEmpty(token))
        // Adicione o token como uma claim
        identity.AddClaim(new Claim("jwt", token));

        return principal;
    }

        // private async Task IncludeJwtTokenAsClaim(ApplicationUser user)
        // {

        //     // Obtém as claims do usuário
        //     var principal = await CreateUserPrincipalAsync(user);

        //     // Gera o token JWT
        //     var token = _tokenGenerator.GenerateToken(principal);

        //     if (!string.IsNullOrEmpty(token))
        //     {
        //         // Adiciona o token como uma claim
        //         var identity = (ClaimsIdentity)principal.Identity!;
        //         identity.AddClaim(new Claim(TokenClaimName, token));

        //     }
        // }
    }

    public interface ITokenGenerator
    {
        string? GenerateToken(ClaimsPrincipal? user);
    }

    public class TokenGenerator : ITokenGenerator
    {
        private readonly IConfiguration _configuration;

        public TokenGenerator(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string? GenerateToken(ClaimsPrincipal? user)
        {

            if (user is null) return default;

            var claims = user.Claims.ToList() ?? new List<Claim>();

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly IHttpContextAccessor _httpContextAccessor;
        // private readonly UserManager<ApplicationUser> _userManager;

        public JwtMiddleware(RequestDelegate next, IConfiguration configuration, IHttpContextAccessor httpContextAccessor/*, UserManager<ApplicationUser> userManager */, ITokenGenerator tokenGenerator)
        {
            _next = next;
            _httpContextAccessor = httpContextAccessor;
            _tokenGenerator = tokenGenerator;
            // _userManager = userManager;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.User.Identity?.IsAuthenticated == true)
            {
                var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (!string.IsNullOrEmpty(userId))
                {
                    var token = _tokenGenerator.GenerateToken(_httpContextAccessor.HttpContext?.User);
                    context.Items["JwtToken"] = token;
                }
            }

            await _next(context);
        }


    }
}