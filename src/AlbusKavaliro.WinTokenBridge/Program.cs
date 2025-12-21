using AlbusKavaliro.WinTokenBridge;
using Microsoft.AspNetCore.Authentication.Negotiate;

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
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization();

builder.Services.AddCors(options =>
{
    // Allow only GET from any origin for public metadata (discovery, jwks, signing-info)
    options.AddPolicy(Policies.CorsMetadata, policy =>
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

app.MapDefaultEndpoints();
app.MapWellKnownEndpoints();
app.MapTokenEndpoint();
app.MapSigningInfoEndpoint();

await app.RunAsync().ConfigureAwait(false);