var builder = DistributedApplication.CreateBuilder(args);

const string otelBasicAuthUserEnv = "OTEL_BASICAUTH_USER";
const string otelBasicAuthPasswordEnv = "OTEL_BASICAUTH_PASSWORD";
string otelBasicAuthUser = Guid.NewGuid().ToString("N");
string otelBasicAuthPassword = Guid.NewGuid().ToString("N");

var tokenServer = builder.AddProject<Projects.ApiService>("tokenserver")
    .WithExternalHttpEndpoints()
    .AsHttp2Service()
    .WithHttpHealthCheck("/health")
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://localhost:21045");

var tokenServerHttp = tokenServer.GetEndpoint("http");

var collectorWithBasicAuth = builder.AddContainer("collectorwithbasicauth", "otel/opentelemetry-collector-contrib:latest")
    .WithBindMount("collector-with-basic-auth.yaml", "/etc/otelcol-contrib/config.yaml", isReadOnly: true)
    .WithEndpoint(11777, 1777, "http", "pprof")
    .WithEndpoint(55679, 55679, "http", "zpages")
    .WithEndpoint(24317, 4317, "http", "grpc")
    .WithEndpoint(24318, 4318, "http", "http")
    .WithContainerRuntimeArgs("--add-host=host.docker.internal:host-gateway")
    .WithEnvironment(otelBasicAuthUserEnv, otelBasicAuthUser)
    .WithEnvironment(otelBasicAuthPasswordEnv, otelBasicAuthPassword)
    .WithOtlpExporter()
    .WithEnvironment("OTEL_EXPORTER_OTLP_API_KEY", builder.Configuration["AppHost:OtlpApiKey"])
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://host.docker.internal:21045");

var gatewayHttp = collectorWithBasicAuth.GetEndpoint("http");

var collectorWithTokenAuth = builder.AddContainer("collectorwithtokenauth", "otel/opentelemetry-collector-contrib:latest")
    .WithBindMount("collector-with-token-auth.yaml", "/etc/otelcol-contrib/config.yaml", isReadOnly: true)
    .WithEndpoint(21777, 1777, "http", "pprof")
    .WithEndpoint(55680, 55679, "http", "zpages")
    .WithEndpoint(14317, 4317, "http", "grpc")
    .WithEndpoint(14318, 4318, "http", "http")
    .WithReference(gatewayHttp)
    .WithReference(tokenServerHttp)
    .WithContainerRuntimeArgs("--add-host=host.docker.internal:host-gateway")
    .WithEnvironment(otelBasicAuthUserEnv, otelBasicAuthUser)
    .WithEnvironment(otelBasicAuthPasswordEnv, otelBasicAuthPassword)
    .WaitFor(tokenServer)
    .WaitFor(collectorWithBasicAuth)
    .WithOtlpExporter()
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://host.docker.internal:21045");;

var otelHttp = collectorWithTokenAuth.GetEndpoint("http");

var businessProcess = builder.AddProject<Projects.DataProducer>("dataproducer")
    .WithReference(tokenServerHttp)
    .WaitFor(collectorWithTokenAuth)
    .WaitFor(tokenServer)
    .WithReference(otelHttp)
    .WithOtlpExporter(OtlpProtocol.HttpProtobuf)
    //.WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", "https://localhost:21046");
    .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", otelHttp);

await builder.Build().RunAsync().ConfigureAwait(false);
