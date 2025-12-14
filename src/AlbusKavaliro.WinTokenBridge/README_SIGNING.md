# Signing Certificates (OIDC)

This document explains how the token service selects signing certificates, how to configure the `Oidc` options, and recommended rotation steps. It matches the behavior implemented in `OidcOptions` and `SigningCertificateProvider`.

## Configuration

Add or update the `Oidc` section in `appsettings.json` or supply values via environment variables. Supported options (see `OidcOptions`):

- `Issuer` — optional canonical issuer URL override (string)
- `SigningCertThumbprint` — optional exact certificate thumbprint to use for signing (string)
- `SigningCertSubjectPattern` — optional regex matched against certificate `Subject` to filter store certificates (string)
- `SigningPfxPath` — optional path to a PFX file containing the signing certificate (string)
- `SigningPfxPassword` — optional password for the PFX file (string)

Example `appsettings.json` snippet:

```json
{
  "Oidc": {
    "Issuer": "https://token.example.local",
    "SigningCertThumbprint": "",
    "SigningCertSubjectPattern": "^CN=signing-",
    "SigningPfxPath": "",
    "SigningPfxPassword": ""
  }
}
```

## How certificates are selected

- If `SigningPfxPath` points to an existing PFX file, the service attempts to load it into memory (ephemeral key set). The PFX is accepted only if it has a private key, an RSA public key, and is currently valid.
- Otherwise the provider enumerates certificates from `LocalMachine\\My`, filtering to certificates that:
  - Have a private key
  - Contain an RSA public key
  - Are currently valid by date (`NotBefore` <= now < `NotAfter`)
  - Match `SigningCertSubjectPattern` if that option is provided (regular expression). Invalid regexes are ignored.
- If `SigningCertThumbprint` is set, the provider will pick the first certificate whose thumbprint matches (spaces ignored, case-insensitive).
- If no thumbprint is provided, the provider selects the first available certificate ordered by `NotAfter` descending (newest expiration first).

## JWKS and public keys

The service publishes JWKS (for example at `/.well-known/jwks`) containing the public keys for all matching valid certificates. Each key's `kid` is the certificate thumbprint. Public-only certificates (exported without private key) are included so clients can discover current verification keys.

## Runtime behavior and rotation

- The provider watches configuration changes (`IOptionsMonitor`). Updating configuration at runtime (via a config provider that supports reload) causes the provider to reload available certificates and the selected signing certificate.
- Rotation approach:
  - Add the new certificate to `LocalMachine\\My` (or provide a new PFX via `SigningPfxPath`) on all nodes.
  - Option A (preferred): set `SigningCertThumbprint` to the new certificate's thumbprint and propagate the config change. The service will pick that certificate immediately.
  - Option B: ensure the new certificate matches `SigningCertSubjectPattern` and has a later `NotAfter` than existing certs; the provider will pick the newest valid cert automatically.
  - Keep the old certificate in the store until all previously issued tokens have expired and clients have received the new JWKS entry.

## Security notes

- Prefer supplying a PFX via a secure channel and limit file system access to the runtime user if using `SigningPfxPath`.
- Do not store private keys in source control or commit them to repositories.
- Use `LocalMachine` store permissions and key protections appropriate for your environment.

## Troubleshooting

- If no signing certificate is selected, confirm:
  - The certificate has a private key and RSA public key.
  - The certificate's validity period includes the current time.
  - `SigningCertSubjectPattern` is correct and compiles as a regex (if used).
- If PFX loading fails, check file permissions and PFX password correctness.
- Use the service logs and Windows Event Viewer to diagnose certificate access errors.

## Reference

- Code: `OidcOptions` (options class) and `SigningCertificateProvider` (selection/rotation logic)
