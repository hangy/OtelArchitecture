using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

public sealed class SigningCertificateProvider : IDisposable
{
    private readonly IDisposable _changeToken;
    private readonly object _lock = new();
    private readonly TimeProvider _timeProvider;
    private ImmutableList<X509Certificate2> _available = [];
    private X509Certificate2? _signingCert;
    private readonly IOptionsMonitor<OidcOptions> _opts;
    private readonly bool _allowFallback;
    private RSA? _devFallback;

    public SigningCertificateProvider(IOptionsMonitor<OidcOptions> opts, IHostEnvironment env, TimeProvider timeProvider)
    {
        _opts = opts ?? throw new ArgumentNullException(nameof(opts));
        ArgumentNullException.ThrowIfNull(env);
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

        _allowFallback = env.IsDevelopment();
        if (_allowFallback)
        {
            _devFallback = RSA.Create(2048);
        }

        var changeToken = _opts.OnChange(_ => Reload());
        if (changeToken is null)
        {
            throw new InvalidOperationException("Failed to register for options change notifications.");
        }

        _changeToken = changeToken;
        Reload();
    }

    private void Reload()
    {
        var opts = _opts.CurrentValue;
        var certs = GetAvailableCerts(opts?.SigningCertSubjectPattern);

        lock (_lock)
        {
            foreach (var c in _available) c.Dispose();
            _available = certs;
            _signingCert = SelectSigningCert(opts, certs);
        }
    }

    public IEnumerable<X509Certificate2> GetAvailable()
    {
        lock (_lock) { return _available; }
    }

    public X509Certificate2? GetSigningCert()
    {
        lock (_lock) { return _signingCert; }
    }

    public bool IsUsingFallback()
    {
        lock (_lock) { return _signingCert == null && _devFallback != null; }
    }

    public SigningCredentials? GetSigningCredentials()
    {
        var cert = GetSigningCert();
        if (cert != null) return new SigningCredentials(new X509SecurityKey(cert) { KeyId = cert.Thumbprint }, SecurityAlgorithms.RsaSha256);
        if (_devFallback != null) return new SigningCredentials(new RsaSecurityKey(_devFallback) { KeyId = "key-1" }, SecurityAlgorithms.RsaSha256);
        return null;
    }

    private ImmutableList<X509Certificate2> GetAvailableCerts(string? subjectPattern)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var certs = store.Certificates
            .Cast<X509Certificate2>()
            .Where(c => c.NotBefore <= now && c.NotAfter > now && c.HasPrivateKey && c.GetRSAPublicKey() != null);

        if (!string.IsNullOrWhiteSpace(subjectPattern))
        {
            try
            {
                var rx = new System.Text.RegularExpressions.Regex(subjectPattern);
                certs = certs.Where(c => !string.IsNullOrWhiteSpace(c.Subject) && rx.IsMatch(c.Subject));
            }
            catch
            {
                // ignore invalid regex
            }
        }

        return [..certs.OrderByDescending(c => c.NotAfter)];
    }

    private static X509Certificate2? SelectSigningCert(OidcOptions? opts, ImmutableList<X509Certificate2> certs)
    {
        if (!string.IsNullOrWhiteSpace(opts?.SigningCertThumbprint))
        {
            var cleaned = opts.SigningCertThumbprint!.Replace(" ", string.Empty);
            var byThumb = certs.FirstOrDefault(c => string.Equals(c.Thumbprint?.Replace(" ", string.Empty), cleaned, StringComparison.OrdinalIgnoreCase));
            if (byThumb != null) return byThumb;
        }

        return certs.FirstOrDefault();
    }

    public void Dispose()
    {
        _changeToken?.Dispose();
        _devFallback?.Dispose();
        foreach (var c in _available) c.Dispose();
        _available.Clear();
    }
}