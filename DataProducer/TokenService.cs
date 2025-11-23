// Source - https://stackoverflow.com/a/73123449
// Posted by Peter Csala, modified by community. See post 'Timeline' for change history
// Retrieved 2025-11-23, License - CC BY-SA 4.0

using System.Net.Http.Json;
using System.Reflection;

namespace DataProducer;

public interface ITokenService
{
    ValueTask<Token?> GetTokenAsync(CancellationToken cancellationToken = default);

    ValueTask<Token?> RefreshTokenAsync(CancellationToken cancellationToken = default);
}

public class TokenService(HttpClient httpClient) : ITokenService
{
    private Token? _token;

    private DateTimeOffset _lastRefreshed = DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public async ValueTask<Token?> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        if (_token is null)
        {
            return await RefreshTokenAsync(cancellationToken).ConfigureAwait(false);
        }

        return _token!;
    }

    /// <inheritdoc />
    public async ValueTask<Token?> RefreshTokenAsync(CancellationToken cancellationToken = default)
    {
        _token = await httpClient.GetFromJsonAsync<Token>("http://tokenserver/token", cancellationToken).ConfigureAwait(false);
        _lastRefreshed = DateTimeOffset.UtcNow;
        return _token;
    }
}
