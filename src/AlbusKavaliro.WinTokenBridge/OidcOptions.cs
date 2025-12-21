namespace AlbusKavaliro.WinTokenBridge;

public class OidcOptions
{
    /// <summary>
    /// Canonical issuer override (important when different callers reach the service via different hosts,
    // e.g. Aspire service discovery vs Docker containers).
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// The thumbprint of the certificate that should be used for signing tokens.
    /// If set, <see cref="SigningCertificateProvider"/> will prefer a matching certificate
    /// from the local machine store or the supplied PFX when selecting the signing key.
    /// </summary>
    public string? SigningCertThumbprint { get; set; }

    /// <summary>
    /// A regular expression used to match the subject of certificates in the local machine store.
    /// This is applied by <see cref="SigningCertificateProvider"/> to filter available certs.
    /// </summary>
    public string? SigningCertSubjectPattern { get; set; }

    /// <summary>
    /// Optional path to a PFX file that contains the signing certificate. When present, the
    /// service will attempt to load the certificate (EphemeralKeySet) and use it if valid.
    /// </summary>
    public string? SigningPfxPath { get; set; }

    /// <summary>
    /// Password for the PFX referenced by <see cref="SigningPfxPath"/>. Only used if a PFX path
    /// is supplied.
    /// </summary>
    public string? SigningPfxPassword { get; set; }

    /// <summary>
    /// One or more audiences to set on issued tokens (maps to the JWT "aud" claim).
    /// Configure as a collection. A token issued in a single request will only be
    /// valid for a single audience (the client must request a `client_id`).
    /// </summary>
    public IReadOnlyCollection<string>? Audiences { get; set; }
}
