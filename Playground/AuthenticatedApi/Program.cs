using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateSlimBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddAuthentication().AddJwtBearer();
builder.Services.AddAuthorization();

builder.Services.Configure<JwtBearerOptions>("Bearer", options =>
{
    // Use backchannel to enable Aspire's internal DNS resolution within the distributed application
    var factory = builder.Services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();
    options.Backchannel = factory.CreateClient();

    // Manually fetch JWKS since automatic discovery fails due to HTTPS requirement
    var response = options.Backchannel.GetAsync("http://tokenserver/.well-known/openid-configuration").Result;
    var config = response.Content.ReadFromJsonAsync<OpenIdConnectConfiguration>().Result;
    var jwksResponse = options.Backchannel.GetAsync(config.JwksUri).Result;
    var jwks = jwksResponse.Content.ReadFromJsonAsync<JsonWebKeySet>().Result;
    options.TokenValidationParameters.IssuerSigningKeys = jwks.Keys;

    // Disable automatic configuration manager
    options.ConfigurationManager = null;
});

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

Todo[] sampleTodos =
[
    new(1, "Walk the dog"),
    new(2, "Do the dishes", DateOnly.FromDateTime(DateTime.Now)),
    new(3, "Do the laundry", DateOnly.FromDateTime(DateTime.Now.AddDays(1))),
    new(4, "Clean the bathroom"),
    new(5, "Clean the car", DateOnly.FromDateTime(DateTime.Now.AddDays(2)))
];

var todosApi = app.MapGroup("/todos");
todosApi.MapGet("/", () => sampleTodos)
        .WithName("GetTodos")
        .RequireAuthorization();

todosApi.MapGet("/{id}", Results<Ok<Todo>, NotFound> (int id) =>
    sampleTodos.FirstOrDefault(a => a.Id == id) is { } todo
        ? TypedResults.Ok(todo)
        : TypedResults.NotFound())
    .WithName("GetTodoById")
    .RequireAuthorization();

app.Run();

public record Todo(int Id, string? Title, DateOnly? DueBy = null, bool IsComplete = false);

[JsonSerializable(typeof(Todo[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{

}
