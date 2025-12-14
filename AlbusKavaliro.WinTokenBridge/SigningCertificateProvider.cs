using System.Collections.Immutable;
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

    public SigningCertificateProvider(IOptionsMonitor<OidcOptions> opts, IHostEnvironment env, TimeProvider timeProvider)
    {
        _opts = opts ?? throw new ArgumentNullException(nameof(opts));
        ArgumentNullException.ThrowIfNull(env);
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

        // No development fallback allowed for security/consistency reasons.

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
        var certs = GetAvailableCerts(opts);

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

    public SigningCredentials? GetSigningCredentials()
    {
        var cert = GetSigningCert();
        if (cert != null) return new SigningCredentials(new X509SecurityKey(cert) { KeyId = cert.Thumbprint }, SecurityAlgorithms.RsaSha256);
        return null;
    }

    private ImmutableList<X509Certificate2> GetAvailableCerts(OidcOptions? opts)
    {
        var builder = ImmutableList.CreateBuilder<X509Certificate2>();
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        // If a PFX path is explicitly provided in options, try to load it into memory
        // (EphemeralKeySet so we don't persist or import into the machine store).
        try
        {
            var pfxPath = opts?.SigningPfxPath;
            if (!string.IsNullOrWhiteSpace(pfxPath) && File.Exists(pfxPath))
            {
                var password = opts?.SigningPfxPassword;
                var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password, X509KeyStorageFlags.EphemeralKeySet);
                // accept only certs with private key and RSA public key and valid dates
                if (cert.HasPrivateKey && cert.GetRSAPublicKey() != null && cert.NotBefore <= now && cert.NotAfter > now)
                {
                    builder.Add(cert);
                }
                else
                {
                    cert.Dispose();
                }
            }
        }
        catch
        {
            // ignore PFX load failures; fallback to store-based certificates below
        }

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var storeCerts = store.Certificates
            .Cast<X509Certificate2>()
            .Where(c => c.NotBefore <= now && c.NotAfter > now && c.HasPrivateKey && c.GetRSAPublicKey() != null);

        var subjectPattern = opts?.SigningCertSubjectPattern;
        if (!string.IsNullOrWhiteSpace(subjectPattern))
        {
            try
            {
                var rx = new System.Text.RegularExpressions.Regex(subjectPattern);
                storeCerts = storeCerts.Where(c => !string.IsNullOrWhiteSpace(c.Subject) && rx.IsMatch(c.Subject));
            }
            catch
            {
                // ignore invalid regex
            }
        }

        foreach (var c in storeCerts.OrderByDescending(c => c.NotAfter))
        {
            // Attempt to create a usable X509Certificate2 instance without exporting the private key.
            // Use the constructor that takes the existing certificate handle; on Windows this preserves access
            // to non-exportable private keys when running in the same user/machine context.
            try
            {
                var clone = new X509Certificate2(c);
                builder.Add(clone);
            }
            catch
            {
                try
                {
                    // Fallback: try exporting public cert only (no private key) so it can still appear in JWKS.
                    var exported = c.Export(X509ContentType.Cert);
                    var pubOnly = X509CertificateLoader.LoadCertificate(exported);
                    builder.Add(pubOnly);
                }
                catch
                {
                    // ignore certificates that cannot be cloned or exported
                }
            }
        }

        return builder.ToImmutable();
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
        foreach (var c in _available) c.Dispose();
        _available.Clear();
    }
}