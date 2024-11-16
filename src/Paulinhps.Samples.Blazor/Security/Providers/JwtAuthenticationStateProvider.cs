using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace Paulinhps.Samples.Blazor.Security.Providers
{
    public class JwtAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public JwtAuthenticationStateProvider(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var user = _httpContextAccessor.HttpContext?.User ?? new ClaimsPrincipal(new ClaimsIdentity());
            return Task.FromResult(new AuthenticationState(user));
        }

        public string? GetJwtToken()
        {
            // JWT armazenado em HttpContext.Items no middleware
            return _httpContextAccessor.HttpContext?.Items["JwtToken"] as string;
        }
    }
}