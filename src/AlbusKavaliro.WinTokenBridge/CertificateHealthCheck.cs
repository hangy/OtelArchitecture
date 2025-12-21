using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AlbusKavaliro.WinTokenBridge;

public class CertificateHealthCheck : IHealthCheck
{
    private readonly SigningCertificateProvider _provider;
    private readonly TimeProvider _timeProvider;

    public CertificateHealthCheck(SigningCertificateProvider provider, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _provider = provider;
        _timeProvider = timeProvider;
    }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var cert = _provider.GetSigningCert();
        if (cert == null) return Task.FromResult(HealthCheckResult.Unhealthy("No signing certificate available"));
        var now = _timeProvider.GetUtcNow();
        if (cert.NotBefore > now || cert.NotAfter <= now)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Signing certificate not valid by time"));
        }

        return Task.FromResult(HealthCheckResult.Healthy($"Signing cert: {cert.Thumbprint} until {cert.NotAfter:u}"));
    }
}
