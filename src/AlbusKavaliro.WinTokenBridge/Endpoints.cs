namespace AlbusKavaliro.WinTokenBridge;

internal sealed class Endpoints
{
    public const string SigningInfo = "/signing-info";
    public const string Token = "/token";
    internal sealed class WellKnown
    {
        public const string Prefix = "/.well-known";   
        public const string OpenIdConfiguration = "/openid-configuration";
        public const string Jwks = "/jwks";
    }
}
