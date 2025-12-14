using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;

const string CorsMetadataPolicy = "Metadata";

var builder = WebApplication.CreateBuilder(args);

// Register options and provider
builder.Services.Configure<OidcOptions>(builder.Configuration.GetSection("Oidc"));
builder.Services.AddSingleton<SigningCertificateProvider>();
builder.Services.AddSingleton<CertificateHealthCheck>();
builder.Services.AddHealthChecks().AddCheck<CertificateHealthCheck>("signing-cert");

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddProblemDetails();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization();

builder.Services.AddCors(options =>
{
    // Allow only GET from any origin for public metadata (discovery, jwks, signing-info)
    options.AddPolicy(CorsMetadataPolicy, policy =>
    {
        policy.AllowAnyOrigin()
              .WithMethods(HttpMethod.Get.Method)
              .AllowAnyHeader();
    });

    // Default policy: deny cross-origin requests by default. Use endpoint-specific RequireCors for allowed endpoints.
    options.AddDefaultPolicy(policy =>
    {
        policy.SetIsOriginAllowed(origin => false);
    });
});

var app = builder.Build();

// Register CORS middleware. The default policy denies cross-origin requests;
// endpoint-specific policies are applied with RequireCors.
app.UseCors();

// Configure the HTTP request pipeline.
app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

static ClaimsIdentity MapCurrentUserToOpenIdClaims(ClaimsPrincipal user)
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

// --- ENDPUNKT 1: Token Ausgabe (Geschützt durch Windows Auth) ---
app.MapGet("/token", (HttpContext ctx, SigningCertificateProvider provider, TimeProvider timeProvider, IOptions<OidcOptions> opts) =>
{
    if (ctx.User.Identity is not ClaimsIdentity user || !user.IsAuthenticated) return Results.Unauthorized();

    var creds = provider.GetSigningCredentials();
    if (creds == null)
    {
        // No signing credentials available and fallback not allowed -> service unavailable
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }

    // Token Descriptor erstellen
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
}).RequireAuthorization(); // <--- Erzwingt Kerberos Challenge

// --- ENDPUNKT 2: Discovery Document (.well-known) ---
app.MapGet("/.well-known/openid-configuration", (HttpContext ctx, IOptions<OidcOptions> opts) =>
{
    var baseUrl = opts.Value.Issuer ?? $"{ctx.Request.Scheme}://{ctx.Request.Host}";
    var config = new OpenIdConnectConfiguration
    {
        Issuer = baseUrl,
        JwksUri = $"{baseUrl}/.well-known/jwks",
        AuthorizationEndpoint = $"{baseUrl}/token", // Etwas "fake", da wir keinen UI-Flow haben
        TokenEndpoint = $"{baseUrl}/token"
    };
    config.ResponseTypesSupported.Add("token");
    config.IdTokenSigningAlgValuesSupported.Add("RS256");
    return Results.Json(config);
}).RequireCors(CorsMetadataPolicy);

// --- ENDPUNKT 3: Public Key (JWKS) ---
app.MapGet("/.well-known/jwks", (SigningCertificateProvider provider) =>
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

    // If no certs found, return 503 Service Unavailable (no fallback in production or dev)
    if (keys.Count == 0)
    {
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }

    return Results.Json(new { keys = keys }, contentType: "application/jwk-set+json");
}).RequireCors(CorsMetadataPolicy);

// Operational endpoint: show which cert is currently selected for signing (thumbprint + expiry)
app.MapGet("/signing-info", (SigningCertificateProvider provider) =>
{
    var cert = provider.GetSigningCert();
    if (cert == null)
    {
        return Results.Json(new { present = false });
    }

    return Results.Json(new { present = true, kid = cert.Thumbprint, notBefore = cert.NotBefore, notAfter = cert.NotAfter, subject = cert.Subject });
}).RequireCors(CorsMetadataPolicy);

app.MapDefaultEndpoints();

await app.RunAsync().ConfigureAwait(false);