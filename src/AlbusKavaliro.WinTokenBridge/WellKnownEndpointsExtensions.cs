using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AlbusKavaliro.WinTokenBridge;

internal static class EndpointExtensions
{
    extension(IEndpointRouteBuilder endpoints)
    {
        public RouteGroupBuilder MapWellKnownEndpoints()
        {
            var wellKnown = endpoints.MapGroup(Endpoints.WellKnown.Prefix)
                .RequireCors(Policies.CorsMetadata);
            wellKnown.MapOpenIdConfigurationEndpoint();
            wellKnown.MapJwksEndpoint();
            return wellKnown;
        }
    }

    extension(RouteGroupBuilder group)
    {
        public RouteHandlerBuilder MapOpenIdConfigurationEndpoint()
        {
            return group.MapGet(Endpoints.WellKnown.OpenIdConfiguration, static (HttpContext ctx, IOptions<OidcOptions> opts) =>
            {
                var baseUrl = opts.Value.Issuer ?? $"{ctx.Request.Scheme}://{ctx.Request.Host}";
                var config = new OpenIdConnectConfiguration
                {
                    Issuer = baseUrl,
                    JwksUri = $"{baseUrl}{Endpoints.WellKnown.Prefix}{Endpoints.WellKnown.Jwks}",
                    AuthorizationEndpoint = $"{baseUrl}/{Endpoints.Token}",
                    TokenEndpoint = $"{baseUrl}{Endpoints.Token}"
                };
                config.ResponseTypesSupported.Add("token");
                config.IdTokenSigningAlgValuesSupported.Add("RS256");
                return Results.Json(config);
            });
        }

        public RouteHandlerBuilder MapJwksEndpoint()
        {
            return group.MapGet(Endpoints.WellKnown.Jwks, static (SigningCertificateProvider provider) =>
            {
                var keys = new List<object>();

                var certs = provider.GetAvailable();
                foreach (var cert in certs)
                {
                    try
                    {
                        using var pubRsa = cert.GetRSAPublicKey();
                        if (pubRsa == null) continue;
                        var parameters = pubRsa.ExportParameters(false);
                        // include x5c certificate chain entry for clients that expect it
                        var x5c = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
                        keys.Add(new
                        {
                            kty = "RSA",
                            kid = cert.Thumbprint,
                            use = "sig",
                            alg = "RS256",
                            n = Base64UrlEncoder.Encode(parameters.Modulus),
                            e = Base64UrlEncoder.Encode(parameters.Exponent),
                            x5c = new[] { x5c }
                        });
                    }
                    catch
                    {
                        // ignore certs that cannot be exported as RSA public params
                    }
                }

                // If no certs found, return 503 Service Unavailable
                if (keys.Count == 0)
                {
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }

                return Results.Json(new { keys = keys }, contentType: "application/jwk-set+json");
            });
        }
    }
}
