namespace ApiService;

internal static class SigningInfoEndpointExtensions
{
    extension(IEndpointRouteBuilder endpoints)
    {
        public RouteHandlerBuilder MapSigningInfoEndpoint()
        {
            return endpoints.MapGet(Endpoints.SigningInfo, (SigningCertificateProvider provider) =>
            {
                var cert = provider.GetSigningCert();
                if (cert == null)
                {
                    return Results.Json(new { present = false });
                }

                return Results.Json(new { present = true, kid = cert.Thumbprint, notBefore = cert.NotBefore, notAfter = cert.NotAfter, subject = cert.Subject });
            }).RequireCors(Policies.CorsMetadata);
        }
    }
}
