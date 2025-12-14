using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace ApiService;

internal static class TokenEndpointExtensions
{
    extension(IEndpointRouteBuilder endpoints)
    {
        public RouteHandlerBuilder MapTokenEndpoint()
        {
            return endpoints.MapGet(Endpoints.Token, (HttpContext ctx, SigningCertificateProvider provider, TimeProvider timeProvider, IOptions<OidcOptions> opts) =>
            {
                if (ctx.User.Identity is not ClaimsIdentity user || !user.IsAuthenticated) return Results.Unauthorized();

                var creds = provider.GetSigningCredentials();
                if (creds == null)
                {
                    // No signing credentials available and fallback not allowed -> service unavailable
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = MapCurrentUserToOpenIdClaims(ctx.User),
                    Expires = timeProvider.GetUtcNow().AddHours(1).UtcDateTime,
                    Issuer = opts.Value.Issuer ?? $"{ctx.Request.Scheme}://{ctx.Request.Host}",
                    Audience = "my-app",
                    SigningCredentials = creds
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDescriptor);

                return Results.Ok(new { access_token = tokenHandler.WriteToken(token), token_type = "Bearer" });
            }).RequireAuthorization();
        }
    }

    extension(ClaimsPrincipal user)
    {
        private ClaimsIdentity MapCurrentUserToOpenIdClaims()
        {
            ArgumentNullException.ThrowIfNull(user);

            if (user.Identity is not ClaimsIdentity identity || !identity.IsAuthenticated)
            {
                throw new InvalidOperationException("User is not authenticated.");
            }

            var newIdentity = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, identity.Name!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString())
            ]);

            var sid = user.FindFirst(ClaimTypes.PrimarySid);
            if (sid != null)
            {
                newIdentity.AddClaim(sid);
            }

            foreach (var group in user.Claims.Where(c => c.Type == identity.RoleClaimType))
            {
                newIdentity.AddClaim(new Claim(ClaimTypes.Role, group.Value));
            }

            return newIdentity;
        }
    }
}
