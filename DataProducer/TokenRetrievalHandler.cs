// Source - https://stackoverflow.com/a/73247376
// Posted by Peter Csala, modified by community. See post 'Timeline' for change history
// Retrieved 2025-11-23, License - CC BY-SA 4.0

using System;
using System.Net.Http.Headers;
using Polly;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Logging;

namespace DataProducer;

public class TokenRetrievalHandler(ITokenService tokenService, ILogger<TokenRetrievalHandler> logger) : DelegatingHandler
{
    private const string TokenRetrieval = nameof(TokenRetrieval);
    private const string TokenKey = nameof(TokenKey);

    private readonly static ResiliencePropertyKey<Token> s_tokenKey = new(TokenKey);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        logger.LogDebug("TokenRetrievalHandler invoked to add authorization header.");

        var context = request.GetResilienceContext();

        Token? token = null;
        if (context is null)
        {
            // No resilience context available - fetch token directly.
            token = await tokenService.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            if (!context.Properties.TryGetValue(s_tokenKey, out token))
            {
                token = await tokenService.GetTokenAsync(cancellationToken).ConfigureAwait(false);
                if (token is not null)
                {
                    context.Properties.Set(s_tokenKey, token);
                }
            }
        }

        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(token.token_type, token.access_token);
        }

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
