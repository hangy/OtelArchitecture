public class OidcOptions
{
    /// <summary>
    /// Canonical issuer override (important when different callers reach the service via different hosts,
    // e.g. Aspire service discovery vs Docker containers).
    /// </summary>
    public string? Issuer { get; set; }
    public string? SigningCertThumbprint { get; set; }
    public string? SigningCertSubjectPattern { get; set; }
    public string? SigningPfxPath { get; set; }
    public string? SigningPfxPassword { get; set; }
}
