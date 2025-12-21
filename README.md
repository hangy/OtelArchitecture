
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
