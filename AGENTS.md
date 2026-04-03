# legion-crypt Agent Notes

## Scope

`legion-crypt` handles cryptography and secret workflows for Legion: cipher ops, Vault integration, JWT/JWKS verification, key lifecycle, mTLS, and lease/token renewers.

## Fast Start

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## Primary Entry Points

- `lib/legion/crypt.rb`
- `lib/legion/crypt/cipher.rb`
- `lib/legion/crypt/jwt.rb`
- `lib/legion/crypt/jwks_client.rb`
- `lib/legion/crypt/vault.rb`
- `lib/legion/crypt/lease_manager.rb`
- `lib/legion/crypt/token_renewer.rb`
- `lib/legion/crypt/mtls.rb`

## Guardrails

- Treat all changes as security-sensitive. Never log secrets, tokens, private keys, or decrypted plaintext.
- Preserve JWT behavior across HS256/RS256 and external JWKS validation.
- Keep Vault-dependent logic optional and safely guarded for environments without Vault.
- Background renewal/rotation threads must stop cleanly on shutdown and handle failure with bounded retry.
- Maintain compatibility for Kerberos, LDAP, and JWT Vault auth paths.
- Cryptographic defaults and key lifecycle behavior are contract-sensitive; change only with test coverage.

## Known Risks

- Vault-backed cluster secret sync is inconsistent today: config key mismatch, read/write path mismatch, and push happens before the new secret is stored.
- External JWKS verification currently accepts tokens without issuer/audience enforcement unless the caller passes both explicitly; fail closed when touching this path.
- Multi-cluster Vault behavior has correctness gaps around LDAP token propagation, default-cluster routing, and lease-manager client selection.
- SPIFFE X.509 fetch currently falls back to a self-signed SVID on Workload API failure; treat that path as security-sensitive and avoid expanding the fallback behavior.
- `Ed25519` and `Erasure` include helper paths that call `Legion::Crypt::Vault.read/write` directly; verify runtime behavior before relying on those helpers.
- Current specs pass, but some of the highest-risk paths above are under-covered or only covered with mocks that preserve the existing behavior.

## Validation

- Run targeted specs for changed auth/crypto paths first.
- Before handoff, run full `bundle exec rspec` and `bundle exec rubocop`.
