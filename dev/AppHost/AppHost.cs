using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var builder = DistributedApplication.CreateBuilder(args);

const string otelBasicAuthUserEnv = "OTEL_BASICAUTH_USER";
const string otelBasicAuthPasswordEnv = "OTEL_BASICAUTH_PASSWORD";
string otelBasicAuthUser = Guid.NewGuid().ToString("N");
string otelBasicAuthPassword = Guid.NewGuid().ToString("N");
string audience = Guid.NewGuid().ToString("N");

var tokenServer = builder.AddProject<Projects.AlbusKavaliro_WinTokenBridge>("tokenserver")
    .WithExternalHttpEndpoints()
    .AsHttp2Service()
    .WithHttpHealthCheck("/health")
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://localhost:21045")
    .WithEnvironment("Oidc__Audiences__0", audience);

var tokenServerHttp = tokenServer.GetEndpoint("http");

// For local dev: generate a self-signed dev certificate, export PFX and pass path+password to the token server.
{
    var secretsDir = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), ".secrets"));
    Directory.CreateDirectory(secretsDir);
    var pfxPath = Path.Combine(secretsDir, "tokenserver.pfx");
    var pfxPassword = Guid.NewGuid().ToString("N");

    using var rsa = RSA.Create(2048);
    var req = new CertificateRequest("CN=signing-dev", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    await File.WriteAllBytesAsync(pfxPath, cert.Export(X509ContentType.Pfx, pfxPassword)).ConfigureAwait(false);

    // Pass PFX path and password to the token server process
    tokenServer.WithEnvironment("Oidc__SigningPfxPath", pfxPath)
               .WithEnvironment("Oidc__SigningPfxPassword", pfxPassword)
               // also ensure the issuer is stable
               .WithEnvironment("Oidc__Issuer", "http://host.docker.internal:5479")
               .WithEnvironment("Oidc__SigningCertSubjectPattern", "^CN=signing-dev");
}

var collectorWithBasicAuth = builder.AddContainer("collectorwithbasicauth", "otel/opentelemetry-collector-contrib:latest")
    .WithBindMount("collector-with-basic-auth.yaml", "/etc/otelcol-contrib/config.yaml", isReadOnly: true)
    .WithEndpoint(11777, 1777, "http", "pprof")
    .WithEndpoint(55679, 55679, "http", "zpages")
    .WithEndpoint(24317, 4317, "http", "grpc")
    .WithEndpoint(24318, 4318, "http", "http")
    .WithEnvironment(otelBasicAuthUserEnv, otelBasicAuthUser)
    .WithEnvironment(otelBasicAuthPasswordEnv, otelBasicAuthPassword)
    .WithOtlpExporter()
    .WithEnvironment("OTEL_EXPORTER_OTLP_API_KEY", builder.Configuration["AppHost:OtlpApiKey"])
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://host.docker.internal:21045")
    .WithDeveloperCertificateTrust(true);

var gatewayHttp = collectorWithBasicAuth.GetEndpoint("http");

var collectorWithTokenAuth = builder.AddContainer("collectorwithtokenauth", "otel/opentelemetry-collector-contrib:latest")
    .WithBindMount("collector-with-token-auth.yaml", "/etc/otelcol-contrib/config.yaml", isReadOnly: true)
    .WithEndpoint(21777, 1777, "http", "pprof")
    .WithEndpoint(55680, 55679, "http", "zpages")
    .WithEndpoint(14317, 4317, "http", "grpc")
    .WithEndpoint(14318, 4318, "http", "http")
    .WithReference(gatewayHttp)
    .WithReference(tokenServerHttp)
    .WithEnvironment(otelBasicAuthUserEnv, otelBasicAuthUser)
    .WithEnvironment(otelBasicAuthPasswordEnv, otelBasicAuthPassword)
    .WaitFor(tokenServer)
    .WaitFor(collectorWithBasicAuth)
    .WithOtlpExporter()
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://host.docker.internal:21045")
    .WithDeveloperCertificateTrust(true)
    .WithEnvironment("OTEL_AUDIENCE", audience);

var otelHttp = collectorWithTokenAuth.GetEndpoint("http");

var businessProcess = builder.AddProject<Projects.DataProducer>("dataproducer")
    .WithReference(tokenServerHttp)
    .WaitFor(collectorWithTokenAuth)
    .WaitFor(tokenServer)
    .WithReference(otelHttp)
    .WithOtlpExporter(OtlpProtocol.HttpProtobuf)
    //.WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://localhost:21046");
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", otelHttp)
    .WithEnvironment("OTEL_CLIENT_ID", audience);

var authenticatedApi = builder.AddProject<Projects.AuthenticatedApi>("authenticatedapi")
    .WithReference(tokenServerHttp)
    .WaitFor(tokenServer)
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://localhost:21045");

var someClient = builder.AddProject<Projects.SomeClient>("someclient")
    .WithReference(tokenServerHttp)
    .WaitFor(tokenServer)
    .WithReference(authenticatedApi)
    .WaitFor(authenticatedApi)
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://localhost:21045")
    .WithEnvironment("OTEL_CLIENT_ID", audience);

await builder.Build().RunAsync().ConfigureAwait(false);
