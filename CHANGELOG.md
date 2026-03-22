# Legion::Crypt

## [1.4.6] - 2026-03-21

### Fixed
- Vault URL construction: normalize `address` field that contains a full URL with scheme (e.g. `https://host`) instead of just a hostname, preventing malformed `http://https://host:port` addresses

## [1.4.5] - 2026-03-20

### Changed
- Refactored `Legion::Crypt::TLS` to standard `resolve` pattern: pure config normalizer with port auto-detect, vault URI resolution, legacy key migration, and three verification levels (none/peer/mutual)
- Removed consumer-specific `bunny_options` and `sequel_options` methods (moved to consuming gems)

### Added
- `TLS.resolve(tls_config, port:)` — standard TLS config resolver
- `TLS.migrate_legacy(config)` — backwards-compat mapping for transport's old TLS keys
- `TLS::TLS_PORTS` — known TLS port auto-detection map (5671, 6380, 11207)
- Default `tls:` settings block in `Legion::Crypt::Settings`

## [1.4.4] - 2026-03-18

### Added
- Multi-cluster Vault support: named clusters with `default` pointer in `crypt.vault.clusters`
- `VaultCluster` module: per-cluster `::Vault::Client` management, `connect_all_clusters`
- `LdapAuth` module: LDAP authentication via Vault HTTP API (`auth/ldap/login/:username`)
- `ldap_login_all` authenticates to all LDAP-configured clusters with single credentials
- `VaultRenewer` now renews tokens for all connected clusters
- Backward compatible: single-cluster config (`crypt.vault.address`) still works unchanged

## [1.4.3] - 2026-03-17

### Added
- `Crypt::TLS`: mTLS configuration for RabbitMQ (Bunny) and PostgreSQL (Sequel) connections
- `TLS.ssl_context` builds OpenSSL::SSL::SSLContext with TLS 1.2+ and VERIFY_PEER
- `TLS.bunny_options` and `TLS.sequel_options` generate adapter-specific TLS option hashes
- Configurable cert/key/ca paths via settings with sensible defaults

## [1.4.2] - 2026-03-16

### Added
- `Legion::Crypt::Ed25519`: Ed25519 key generation, signing, verification, Vault key storage
- `Legion::Crypt::PartitionKeys`: HKDF-based per-tenant key derivation with AES-256-GCM encrypt/decrypt
- `Legion::Crypt::Erasure`: cryptographic erasure via Vault master key deletion with event emission
- `Legion::Crypt::Attestation`: signed identity claims with Ed25519 signatures and freshness checking
- Dependency: `ed25519` gem ~> 1.3

## [1.4.1] - 2026-03-16

### Added
- `Legion::Crypt::MockVault` in-memory Vault mock for local development mode

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
