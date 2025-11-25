using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var rsaKey = RSA.Create(2048);
var securityKey = new RsaSecurityKey(rsaKey) { KeyId = "key-1" };
var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddProblemDetails();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization();

var app = builder.Build();

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
app.MapGet("/token", (HttpContext ctx) =>
{
    var user = ctx.User.Identity as ClaimsIdentity;
    if (user == null || !user.IsAuthenticated) return Results.Unauthorized();

    // Token Descriptor erstellen
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = MapCurrentUserToOpenIdClaims(ctx.User),
        Expires = DateTime.UtcNow.AddHours(1),
        Issuer = $"{ctx.Request.Scheme}://{ctx.Request.Host}",
        Audience = "my-app",
        SigningCredentials = credentials
    };

    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.CreateToken(tokenDescriptor);

    return Results.Ok(new { access_token = tokenHandler.WriteToken(token), token_type = "Bearer" });
}).RequireAuthorization(); // <--- Erzwingt Kerberos Challenge

// --- ENDPUNKT 2: Discovery Document (.well-known) ---
app.MapGet("/.well-known/openid-configuration", (HttpContext ctx) =>
{
    var baseUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
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
});

// --- ENDPUNKT 3: Public Key (JWKS) ---
app.MapGet("/.well-known/jwks", () =>
{
    // Konvertiert unseren RSA Public Key in das JWK JSON Format
    var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
    var jwks = new JsonWebKeySet();
    jwks.Keys.Add(jwk);
    return Results.Json(jwks, contentType: "application/jwk-set+json");
});

app.MapDefaultEndpoints();

await app.RunAsync().ConfigureAwait(false);