# Legion::Crypt

## [Unreleased]

## [1.4.0] - 2026-03-16

### Added
- `JwksClient` module: fetch, parse, and cache public keys from JWKS endpoints (TTL 3600s, thread-safe)
- `JWT.verify_with_jwks` for RS256 token verification against external identity providers (Entra ID, Bot Framework)
- Multi-issuer support via `issuers:` array parameter
- Audience validation via `audience:` parameter
- `Crypt.verify_external_token` convenience method

## [1.3.0] - 2026-03-16

### Added
- `LeaseManager` singleton for dynamic Vault secret lease management
- Named lease definitions in `crypt.vault.leases` settings
- Boot-time lease fetch with data caching
- Background renewal thread with rotation detection
- Settings push-back on credential rotation via reverse index
- `lease://name#key` URI references resolved by Settings resolver

## v1.2.1

### Fixed
- `validate_hex` and `set_cluster_secret` now handle leading zeros correctly by padding the
  base-32 round-trip result back to the original string length. Previously, secrets whose
  hex representation started with one or more zero bytes would fail validation and cause
  `find_cluster_secret` to return nil non-deterministically.

### Added
- Comprehensive spec coverage for `Legion::Crypt::VaultJwtAuth` (`.login`, `.login!`,
  `.worker_login`, `AuthError`, constants).
- `after` hook in `cluster_secret_spec` to restore `Legion::Settings[:crypt][:cluster_secret]`
  between examples, eliminating ordering-dependent state pollution.
- TODO comments in `vault_spec` for tests that require live Vault connectivity.

## v1.2.0
Moving from BitBucket to GitHub. All git history is reset from this point on
