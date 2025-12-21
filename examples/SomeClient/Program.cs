using System.Net;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.HttpResults;

var builder = WebApplication.CreateSlimBuilder(args);

builder.AddServiceDefaults();

builder.Services.ConfigureHttpJsonOptions(static options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

builder.Services.AddHttpClient<TokenClient>(static client =>
{
    client.BaseAddress = new("http://tokenserver");
})
.ConfigurePrimaryHttpMessageHandler(static services => 
{
    HttpClientHandler handler = new()
    {
        Credentials = CredentialCache.DefaultNetworkCredentials
    };
    return handler;
});

builder.Services.AddHttpClient<TodoServiceClient>(static client => { client.BaseAddress = new("http://authenticatedapi"); });

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

var todosApi = app.MapGroup("/todos");
todosApi.MapGet("/", static async (TodoServiceClient todos, CancellationToken cancellationToken) => await todos.GetTodosAsync(cancellationToken))
        .WithName("GetTodos");

todosApi.MapGet("/{id}", static async Task<Results<Ok<Todo>, NotFound>> (int id, TodoServiceClient todos, CancellationToken cancellationToken) =>
{
    var todo = await todos.GetAsync(id, cancellationToken);
    return todo is not null
        ? TypedResults.Ok(todo)
        : TypedResults.NotFound();
})
.WithName("GetTodoById");

app.Run();

public record Todo(int Id, string? Title, DateOnly? DueBy = null, bool IsComplete = false);

[JsonSerializable(typeof(Todo[]))]
[JsonSerializable(typeof(Todo))]
[JsonSerializable(typeof(TokenClient.TokenResponse))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{

}

public class TodoServiceClient(HttpClient http, TokenClient tokenClient)
{
    public async Task<Todo[]> GetTodosAsync(CancellationToken cancellationToken)
    {
        var token = await tokenClient.GetTokenAsync(cancellationToken);
        http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return await http.GetFromJsonAsync<Todo[]>("http://authenticatedapi/todos", cancellationToken) ?? [];
    }

    public async Task<Todo?> GetAsync(int id, CancellationToken cancellationToken)
    {
        var token = await tokenClient.GetTokenAsync(cancellationToken);
        http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return await http.GetFromJsonAsync<Todo>($"http://authenticatedapi/todos/{id}", cancellationToken);
    }
}

public class TokenClient(HttpClient http)
{
    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        using FormUrlEncodedContent form = new([new KeyValuePair<string, string>("client_id", Environment.GetEnvironmentVariable("OTEL_CLIENT_ID") ?? "")]);
        using var resp = await http.PostAsync("http://tokenserver/token", form, cancellationToken).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        var response = await resp.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: cancellationToken).ConfigureAwait(false);
        return response?.AccessToken ?? string.Empty;
    }

    public record TokenResponse([property: JsonPropertyName("access_token")] string AccessToken);
}