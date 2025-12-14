// Source - https://stackoverflow.com/a/73123449
// Posted by Peter Csala, modified by community. See post 'Timeline' for change history
// Retrieved 2025-11-23, License - CC BY-SA 4.0

using System;
using System.Net.Http.Json;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace DataProducer;

public interface ITokenService
{
    ValueTask<Token?> GetTokenAsync(CancellationToken cancellationToken = default);

    ValueTask<Token?> RefreshTokenAsync(CancellationToken cancellationToken = default);
}

public class TokenService(HttpClient httpClient, TimeProvider timeProvider) : ITokenService
{
    private static readonly ActivitySource s_activitySource = new("DataProducer.TokenService");
    private static readonly Meter s_meter = new("DataProducer.TokenService");
    private static readonly Counter<long> s_tokenRefreshes = s_meter.CreateCounter<long>("token_refreshes", description: "Number of times a new token was retrieved");

    private Token? _token;

    private DateTimeOffset _lastRefreshed = DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public async ValueTask<Token?> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        using var activity = s_activitySource.StartActivity("GetToken");

        if (_token is null || DateTimeOffset.UtcNow - _lastRefreshed > TimeSpan.FromMinutes(5))
        {
            activity?.SetTag("token.action", "refresh");
            return await RefreshTokenAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            activity?.SetTag("token.action", "reuse");
            return _token!;
        }
    }

    /// <inheritdoc />
    public async ValueTask<Token?> RefreshTokenAsync(CancellationToken cancellationToken = default)
    {
        using var activity = s_activitySource.StartActivity("RefreshToken");

        _token = await httpClient.GetFromJsonAsync<Token>("http://tokenserver/token", cancellationToken).ConfigureAwait(false);
        _lastRefreshed = timeProvider.GetUtcNow();

        s_tokenRefreshes.Add(1);
        activity?.SetTag("token.retrieved", true);

        return _token;
    }
}
