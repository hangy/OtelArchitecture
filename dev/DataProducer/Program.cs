using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using DataProducer;
using System.Net;
using Polly;
using Microsoft.Extensions.Http.Resilience;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddTransient<TokenRetrievalHandler>();
builder.Services.ConfigureHttpClientDefaults(options => 
{
    options.ConfigurePrimaryHttpMessageHandler(services => 
    {
        HttpClientHandler handler = new()
        {
            Credentials = CredentialCache.DefaultNetworkCredentials
        };
        return handler;
    });
});

// Extracted method to configure Otlp HttpClients
void ConfigureOtlpHttpClient(IServiceCollection services, string clientName)
{
    services.AddHttpClient(clientName)
        .AddHttpMessageHandler<TokenRetrievalHandler>()
        .AddResilienceHandler(
            "OidcPipeline",
            static (builder, context) =>
            {
                builder.AddRetry(new HttpRetryStrategyOptions
                    {
                        ShouldHandle = static args =>
                        {
                            return ValueTask.FromResult(args is
                            {
                                Outcome.Result.StatusCode:
                                    HttpStatusCode.Unauthorized
                            });
                        },
                        OnRetry = async args =>
                        {
                            ITokenService tokenService = context.ServiceProvider.GetRequiredService<ITokenService>();
                            Token? token = await tokenService.GetTokenAsync(CancellationToken.None).ConfigureAwait(false);
                            if (token is not null)
                            {
                                args.Outcome.Result.RequestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.token_type, token.access_token);
                            }
                        }
                    });
            });
}

ConfigureOtlpHttpClient(builder.Services, "OtlpTraceExporter");
ConfigureOtlpHttpClient(builder.Services, "OtlpMetricExporter");
ConfigureOtlpHttpClient(builder.Services, "OtlpLogExporter");

builder.Services.AddHostedService<Worker>();

using IHost host = builder.Build();

await host.RunAsync().ConfigureAwait(false);