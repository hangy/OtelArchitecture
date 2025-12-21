using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AlbusKavaliro.WinTokenBridge;

internal static class TokenEndpointExtensions
{
    extension(IEndpointRouteBuilder endpoints)
    {
        public RouteHandlerBuilder MapTokenEndpoint()
        {
            return endpoints.MapPost(Endpoints.Token, static async (HttpContext ctx, SigningCertificateProvider provider, TimeProvider timeProvider, IOptionsSnapshot<OidcOptions> opts) =>
            {
                if (ctx.User.Identity is not ClaimsIdentity user || !user.IsAuthenticated)
                {
                    // Requestor is not authenticated; trigger an authentication challenge so the client knows which scheme to use
                    await ctx.ChallengeAsync().ConfigureAwait(false);
                    return Results.StatusCode(StatusCodes.Status401Unauthorized);
                }

                var creds = provider.GetSigningCredentials();
                if (creds == null)
                {
                    // No signing credentials available and fallback not allowed -> service unavailable
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }

                var options = opts.Value;

                // Accept OAuth2-like form-encoded body: client_id is required.
                if (!ctx.Request.HasFormContentType)
                {
                    return TokenError(ctx, "invalid_request", "form content required", StatusCodes.Status400BadRequest);
                }

                var form = await ctx.Request.ReadFormAsync().ConfigureAwait(false);
                var clientId = form[OpenIdConnectParameterNames.ClientId].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(clientId))
                {
                    return TokenError(ctx, "invalid_request", "client_id is required", StatusCodes.Status400BadRequest);
                }

                if (options.Audiences == null || !options.Audiences.Contains(clientId))
                {
                    // Unknown or unauthorized client -> invalid_client per RFC6749
                    return TokenError(ctx, "invalid_client", "unknown or unauthorized client_id", StatusCodes.Status400BadRequest);
                }

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = MapCurrentUserToOpenIdClaims(ctx.User),
                    Expires = timeProvider.GetUtcNow().AddHours(1).UtcDateTime,
                    Issuer = options.Issuer ?? $"{ctx.Request.Scheme}://{ctx.Request.Host}",
                    Audience = clientId,
                    SigningCredentials = creds
                };

                // Optionally set Authorized Party (azp) if different from client
                var requestedAzp = form[JwtRegisteredClaimNames.Azp].FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(requestedAzp))
                {
                    tokenDescriptor.Subject.AddClaim(new Claim(JwtRegisteredClaimNames.Azp, requestedAzp));
                }

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDescriptor);

                // Token responses must not be cached
                ctx.Response.Headers.NoCache();
                
                return Results.Ok(new { access_token = tokenHandler.WriteToken(token), token_type = "Bearer" });
            }).RequireAuthorization();
        }
    }

    private static IResult TokenError(HttpContext ctx, string error, string? description, int statusCode)
    {
        ctx.Response.Headers.NoCache();
        var body = new { error, error_description = description };
        return Results.Json(body, statusCode: statusCode);
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

    extension(IHeaderDictionary headers)
    {
        public void NoCache()
        {
            headers.CacheControl = "no-store";
            headers.Pragma = "no-cache";
        }
    }
}
