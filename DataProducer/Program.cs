using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using DataProducer;
using System.Net;
using Polly;
using Microsoft.Extensions.Http.Resilience;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.AddTransient<TokenRetrievalHandler>();
builder.Services.AddHttpClient<TokenService>().ConfigurePrimaryHttpMessageHandler(services =>
{
    WinHttpHandler handler = new()
    {
        ServerCredentials = CredentialCache.DefaultNetworkCredentials
    };
    return handler;
});

builder.Services.AddHttpClient("OtlpTraceExporter")
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

                        args.Outcome.Result.RequestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.Scheme, token.AccessToken);
                    }
                });
        });
builder.Services.AddHttpClient("OtlpMetricExporter")
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

                        args.Outcome.Result.RequestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.Scheme, token.AccessToken);
                    }
                });
        });
builder.Services.AddHttpClient("OtlpLogExporter")
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

                        args.Outcome.Result.RequestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.Scheme, token.AccessToken);
                    }
                });
        });

builder.Services.AddHostedService<Worker>();

using IHost host = builder.Build();

await host.RunAsync().ConfigureAwait(false);