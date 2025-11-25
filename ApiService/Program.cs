using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;

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

// --- ENDPUNKT 1: Token Ausgabe (Geschützt durch Windows Auth) ---
app.MapGet("/token", (HttpContext ctx) =>
{
    var user = ctx.User.Identity as ClaimsIdentity;
    if (user == null || !user.IsAuthenticated) return Results.Unauthorized();

    // Token Descriptor erstellen
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(
        [
            new Claim(JwtRegisteredClaimNames.Sub, user.Name!), // z.B. DOMAIN\User
            new Claim("upn", user.Name!), 
            // Hier Gruppen aus user.Claims mappen, falls gewünscht
        ]),
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