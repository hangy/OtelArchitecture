
# WinTokenBridge

## Overview

This repository contains small test projects that demonstrate a token service used to authenticate clients (for example: an OpenTelemetry Collector) against an OpenID Connect / token provider running on Windows Server.

This README documents how to deploy the token service to IIS on Windows Server and how to configure the OpenTelemetry Collector to use tokens issued by this service for authentication. It assumes the projects in the `dev/` folder have been built and the resulting binaries are available.

## Prerequisites

- Windows Server 2019 or newer with IIS installed
- .NET SDK matching the projects in this repository (check `global.json`)
- Administrative access to the server to configure IIS and firewall rules

## Build the token service

1. On a developer machine, publish the ASP.NET app (example path: `src/AlbusKavaliro.WinTokenBridge` or `dev/AppHost`) for Release:

```powershell
dotnet publish -c Release -o .\publish
```

1. Copy the `publish` folder to the Windows Server where IIS will host the service (for example `C:\inetpub\wwwroot\TokenService`). Ensure the folder contains the executable and `web.config` (or create one as described below).

## Configure IIS

1. Open `Server Manager` → `Add roles and features` and ensure `Web Server (IIS)` is installed with the `Application Development` features for `.NET` and `ASP.NET`.

1. Open `Internet Information Services (IIS) Manager`.

1. Create a new Application Pool:
   - Name: `TokenServicePool`
   - .NET CLR Version: `No Managed Code` (for out-of-process hosting with ANCM)
   - Managed pipeline mode: `Integrated`

1. Add a new Website or Application:
   - Site name: `TokenService`
   - Physical path: `C:\inetpub\wwwroot\TokenService` (the folder you copied)
   - Application Pool: `TokenServicePool`
   - Binding: set the hostname and port (e.g., `https` on `443` with your certificate). Use a proper hostname instead of 0.0.0.0.

1. Configure HTTPS:
   - Add an SSL certificate to the server and bind it to the site's HTTPS binding.

1. Optional: If the app uses Windows environment variables for URLs, set them in the system-level Environment Variables or in `web.config` as appSettings.

## Firewall and ports

Ensure the server firewall allows inbound traffic on the ports you bind (e.g. `443` for HTTPS). If the collector will be hosted elsewhere, ensure that host can reach the token service URL.

## Configure OpenTelemetry Collector to use token auth

Below is an example snippet adapted from `dev/AppHost/collector-with-token-auth.yaml`. Note the following changes compared to older examples:

- The token service is configured with a collection of allowed audiences (`Oidc:Audiences`).
- When requesting a token clients MUST provide a `client_id` parameter; the issued token will be valid for that single audience (the `aud` claim will contain exactly one value).
 - The token service exposes additional configuration options under the `Oidc` section. See the `OidcOptions` class for details. Important options include:
   - `Issuer`: Canonical issuer override (important when different callers reach the service via different hosts). Set this when the externally-visible issuer differs from the server's local address.
   - `SigningCertThumbprint`: Thumbprint of a certificate in the local machine store to prefer when signing tokens.
   - `SigningCertSubjectPattern`: Regular expression used to match certificate subjects in the local machine store when selecting a signing certificate.
   - `SigningPfxPath`: Optional path to a PFX file that contains the signing certificate. When present the service will attempt to load the PFX (using `EphemeralKeySet`) and use it if valid.
   - `SigningPfxPassword`: Password for the PFX referenced by `SigningPfxPath` (only used if a PFX path is supplied).
   - `Audiences`: One or more audiences to set on issued tokens (maps to the JWT `aud` claim). Configure as a collection. A token issued in a single request will only be valid for a single audience (clients must request a `client_id`).

### collector configuration snippet

```yaml
extensions:
  oidc:
    providers:
      - issuer_url: ${env:TOKENSERVER_HTTP}
        audience: my-app
        username_claim: sub
        groups_claim: role

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        auth:
          authenticator: oidc
      http:
        endpoint: 0.0.0.0:4318
        auth:
          authenticator: oidc

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [someotlp]

  extensions: [oidc]
```

## Getting a token (Windows Integrated Auth)

The token service supports Windows Integrated Authentication for environments where clients can negotiate Kerberos/NTLM with the server. Below are simple examples showing how a client can request a token from the `/token` endpoint. Replace `https://tokens.example.com/token` with your token service URL and supply the `client_id` (audience) you need.

- .NET `HttpClient` (Negotiate/DefaultCredentials):

```csharp
using System.Net.Http;
using System.Collections.Generic;

var handler = new HttpClientHandler { UseDefaultCredentials = true };
using var http = new HttpClient(handler) { BaseAddress = new Uri("https://tokens.example.com") };

var form = new Dictionary<string, string>
{
    ["grant_type"] = "client_credentials",
    ["client_id"] = "my-app"
};

var resp = await http.PostAsync("/token", new FormUrlEncodedContent(form));
resp.EnsureSuccessStatusCode();
var json = await resp.Content.ReadAsStringAsync();
// parse JSON and extract access_token
```

- PowerShell (Invoke-RestMethod with Negotiate):

```powershell
$tokenServer = 'https://tokens.example.com'
$response = Invoke-RestMethod -Uri "$tokenServer/token" -Method Post -Body @{ grant_type = 'client_credentials'; client_id = 'my-app' } -Authentication Negotiate -UseDefaultCredentials
$response.access_token
```

- curl (GSSAPI / Negotiate) — requires curl built with GSSAPI support and a valid Kerberos ticket:

```bash
curl --negotiate -u : -X POST \
  -d "grant_type=client_credentials&client_id=my-app" \
  https://tokens.example.com/token
```

Notes:

- Use HTTPS and trust the server certificate in production.
- When using Kerberos, ensure SPNs and hostnames match the server's certificate and the configured `Issuer` if you override it.
- The examples post a `client_id` which the service maps into the issued token's `aud` claim. Adjust `grant_type` and parameters if your setup requires different flows.

## Using the token with OpenTelemetry .NET clients

OpenTelemetry .NET supports configuring the OTLP exporters to use a custom `HttpClient` (or `HttpClientFactory`) so you can attach authentication headers. See the OpenTelemetry .NET project for details: https://github.com/open-telemetry/opentelemetry-dotnet

In this repository the `dev/DataProducer` project demonstrates how to integrate token retrieval into exporter HTTP requests. The project registers a `TokenRetrievalHandler` which adds an `Authorization: Bearer <token>` header to outgoing OTLP exporter requests when needed.

Two recommended approaches when using `OpenTelemetry.Exporter.OpenTelemetryProtocol` are:

- Configure the exporter to use a named `HttpClient` (recommended when you use `IHttpClientFactory`) and register a `DelegatingHandler` to attach tokens. The `OtlpTraceExporter` and friends will use named clients if available; see the exporter docs for the exact client names.
- Use `OtlpExporterOptions.HttpClientFactory` (when using `HttpProtobuf` protocol) to return an `HttpClient` instance configured with default headers or handlers.

Example (based on `dev/DataProducer/Program.cs`) — registers named OTLP clients and a `TokenRetrievalHandler`:

```csharp
// In Program.cs
builder.Services.AddTransient<TokenRetrievalHandler>();

// Configure the HttpClient used by OTLP exporters to use Windows Integrated Auth when contacting the token server
builder.Services.AddHttpClient("OtlpTraceExporter")
  .AddHttpMessageHandler<TokenRetrievalHandler>();

// For metrics/logs exporters use the same pattern with "OtlpMetricExporter" / "OtlpLogExporter"

// The TokenRetrievalHandler is responsible for requesting a token (using Windows Integrated Auth)
// and adding the Authorization header to the outgoing OTLP request when the exporter receives HTTP 401 responses.
```

If you prefer to configure the exporter directly, use `HttpClientFactory` on `OtlpExporterOptions`:

```csharp
builder.Services.AddOpenTelemetry()
  .WithTracing(tracing => tracing.AddOtlpExporter(o =>
  {
    o.Protocol = OtlpExportProtocol.HttpProtobuf;
    o.HttpClientFactory = () =>
    {
      var handler = new HttpClientHandler { UseDefaultCredentials = true };
      var client = new HttpClient(new DelegatingHandlerWithToken(handler));
      client.BaseAddress = new Uri("https://collector.example.com/v1/traces");
      return client;
    };
  }));

// DelegatingHandlerWithToken would be a small delegating handler that obtains a token (for example via ITokenService)
// and attaches the Authorization header prior to sending the request.
```


References:

- OpenTelemetry .NET repository: https://github.com/open-telemetry/opentelemetry-dotnet
- OTLP exporter docs (HttpClientFactory, Headers, named clients): https://github.com/open-telemetry/opentelemetry-dotnet/blob/main/src/OpenTelemetry.Exporter.OpenTelemetryProtocol/README.md

## Usage notes and tips

- Use HTTPS for all production endpoints and ensure certificates are trusted by clients.
- The `issuer_url` in the collector must exactly match the token issuer's `iss` claim and the service's discovery endpoint if using OIDC discovery.
- If your token service requires client credentials or basic auth for certain flows, configure those credentials as environment variables and keep them out of source control.
- Test locally with `curl` or `OpenID` debug tools to retrieve a token and then call the collector endpoint with an `Authorization: Bearer <token>` header to validate the end-to-end flow.

## Troubleshooting

- Check the Windows Event Viewer and the application's stdout logs (enable `stdoutLogEnabled` in `web.config` temporarily) for startup failures.
- If the collector reports authentication failures, verify the `audience` and `issuer_url` match the token contents.
- Use `jwt.ms` or `jwt.io` to decode tokens and inspect claims during development.

## License

See the repository `LICENSE` file for license details.
