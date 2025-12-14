Configuration and runtime signing notes

Add or update the `Oidc` section in `appsettings.json` or environment variables.

Example `appsettings.json` snippet:

{
  "Oidc": {
    "Issuer": "https://token.example.local",
    "SigningCertThumbprint": "", // optional: exact thumbprint to use
    "SigningCertSubjectPattern": "^CN=signing-" // optional: regex matched against cert Subject
  }
}

Behavior:
- If `SigningCertThumbprint` is set and the cert exists in `LocalMachine\\My`, it will be used for signing.
- Otherwise the newest valid cert matching `SigningCertSubjectPattern` is used.
- JWKS (`/.well-known/jwks`) publishes public keys for all matching valid certs. The `kid` is the certificate thumbprint.
- Changing configuration at runtime (via a config provider that supports reload) will be picked up automatically by the running service (uses `IOptionsSnapshot`).

Rotation guidance:
- Add new cert to LocalMachine\\My on all nodes and ensure it matches the subject pattern or configure its thumbprint.
- Update `SigningCertThumbprint` (if used) or wait until the new cert is newest matching cert. The service will start signing with the new key for new tokens.
- Keep old cert present in the store until existing tokens expire and then remove it. JWKS will still contain both keys during rollover.
