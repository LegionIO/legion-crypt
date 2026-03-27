# Legion::Crypt

## [1.4.21] - 2026-03-27

### Changed
- Replace split `log.error(e.message); log.error(e.backtrace)` patterns with single `Legion::Logging.log_exception` calls in `vault.rb`, `cluster_secret.rb`, and `settings.rb` for structured exception events
- Guard all `log_exception` call sites in `vault.rb`, `settings.rb`, and `cluster_secret.rb` with `defined?(Legion::Logging) && Legion::Logging.respond_to?(:log_exception)` checks; fall back to `Legion::Logging.fatal`/`error` or `warn` to preserve structured logging in environments where `log_exception` is unavailable
- `from_transport` and `cs` rescue blocks in `cluster_secret.rb` now explicitly return `nil` after logging to preserve expected return types

## [1.4.20] - 2026-03-27

### Fixed
- `Vault#read`: unwrap KV v2 response envelope — `logical.read` returns `{data: {keys}, metadata: {}}` for KV v2 mounts; the nested `:data` key is now auto-detected and unwrapped

### Added
- Debug logging throughout Vault auth, read, and cluster connection paths (`vault.rb`, `vault_cluster.rb`, `kerberos_auth.rb`, `lease_manager.rb`)
- `Vault#log_read_context`: logs path and namespace context for each Vault read
- `Vault#unwrap_kv_v2`: detects and unwraps KV v2 envelope pattern
- `VaultCluster`: debug logging for cluster connection, client build, and Kerberos auth flow
- `KerberosAuth`: debug logging for SPN, token exchange, policies, and renewal metadata
- `LeaseManager`: debug logging for lease fetch, renewal, and revocation

## [1.4.19] - 2026-03-26

### Fixed
- `LeaseManager`, `VaultJwtAuth`, `LdapAuth`, `VaultKerberosAuth`: use `renewable?` instead of `renewable` to match Vault gem API
- `LeaseManager#fetch`: handle string/symbol key mismatch between resolver (strings) and cache (symbols)
- `VaultCluster#connect_all_clusters`: set top-level `vault.connected` flag after any cluster connects via Kerberos/LDAP
- `Vault#add_session`: guard `@sessions` with lazy init to prevent nil error when using cluster-based auth

## [1.4.18] - 2026-03-26

### Fixed
- `KerberosAuth.login`: clear `@kerberos_principal` at the start of each login attempt so a failed re-auth does not leave a stale principal from a previous successful login

### Added
- `crypt_spec.rb`: delegation spec for `Legion::Crypt.kerberos_principal`
- `kerberos_auth_spec.rb`: spec verifying stale principal is cleared before a failing login attempt

## [1.4.17] - 2026-03-26

### Added
- Store Kerberos principal after successful SPNEGO authentication (`KerberosAuth.kerberos_principal`)
- Expose `Legion::Crypt.kerberos_principal` delegation

## [1.4.16] - 2026-03-26

### Changed
- `KerberosAuth#exchange_token`: removed namespace clear/restore logic — Kerberos auth is now mounted inside the target namespace, client namespace is preserved so the issued token is scoped correctly
- `VaultCluster#connect_kerberos_cluster`: set token on the cached vault_client after Kerberos auth (`vault_client(name).token = result[:token]`) so the memoized client is immediately usable
- `VaultCluster#build_vault_client`: fall back to `Settings[:crypt][:vault][:vault_namespace]` when `config[:namespace]` is absent, guarded with `defined?(Legion::Settings)`
- `TokenRenewer#stop`: revoke the Vault token on shutdown (only for Kerberos auth_method; token-based clusters are not revoked)
- `LeaseManager#start`: accepts optional `vault_client:` keyword argument; stores and routes `logical.read` through it when provided
- `LeaseManager#shutdown`: routes `sys.revoke` through the cluster vault_client when one was supplied
- `LeaseManager#renew_lease`: routes `sys.renew` through the cluster vault_client when one was supplied
- `Crypt#start_lease_manager`: triggers when `connected_clusters.any?` in addition to the single-cluster `vault.connected` flag; passes the default cluster client to the lease manager

### Added
- `vault_namespace: 'legionio'` default in `Settings.vault` — used as namespace fallback for cluster clients when `config[:namespace]` is not set
- `TokenRenewer#revoke_token` private method: self-revokes the token via `auth_token.revoke_self`, guarded to Kerberos auth_method only

### Fixed
- `TokenRenewer#stop`: skip token revocation when renewal thread is still alive after join timeout to prevent racy revocation against a running thread; log warning instead
- `Crypt#start_lease_manager`: use `vault_settings[:default]` (matching `VaultCluster#default_cluster_name`) instead of the nonexistent `:default_cluster` key so configured default cluster is honored
- `LeaseManager#start`: always assign `@vault_client` before early return so subsequent `shutdown`/`reset!` calls do not use a stale cluster client; clear `@vault_client` in both `shutdown` and `reset!`

## [1.4.15] - 2026-03-26

### Fixed
- Route `get`, `write`, `read`, `delete`, `exist?` through default cluster client when multi-cluster Vault is configured (#1)
- Previously these methods used the global `::Vault` singleton which was never initialized when clusters were present, causing 403 errors against the wrong Vault server

## [1.4.14] - 2026-03-26

### Fixed
- Vault Kerberos auth: send SPNEGO token as HTTP `Authorization` header instead of JSON body (Vault plugin reads headers, not body)
- Vault Kerberos auth: clear client namespace before auth request (Kerberos mount is at root namespace, not child)
- Vault Kerberos auth: use `Vault::SecretAuth#renewable?` accessor (not `#renewable`)

## [1.4.13] - 2026-03-25

### Added
- Kerberos auto-auth to Vault on boot (`auth_method: 'kerberos'` per cluster)
- `KerberosAuth` module: client-side SPNEGO token acquisition via lex-kerberos, Vault token exchange
- `TokenRenewer`: plain-Thread token lifecycle (renew at 75% TTL, re-auth via Kerberos, exponential backoff 30s-10min)
- `kerberos` settings block in vault cluster config (`service_principal`, `auth_path`)
- `auth_method` dispatch in `connect_all_clusters` (kerberos, ldap, token)

### Changed
- Token renewal no longer depends on `Extensions::Actors::Every` (starts at boot, not after extensions load)
- Removed actor-dependent renewer guard from `connect_vault`

## [1.4.12] - 2026-03-25

### Fixed
- Ruby 4.0 compatibility: unfreeze `OpenSSL::SSL::SSLContext::DEFAULT_PARAMS` before requiring vault gem (vault 0.18.x mutates this hash in `Vault.setup!`)

## [1.4.11] - 2026-03-24

### Added
- `Legion::Crypt::Mtls` module: Vault PKI cert issuance with `.issue_cert`, `.enabled?`, `.pki_path`, `.local_ip`; feature-flagged via `security.mtls.enabled`
- `Legion::Crypt::CertRotation` class: background cert rotation at 50% TTL boundary with `#start`, `#stop`, `#rotate!`, `#needs_renewal?`; emits `cert.rotated` event via `Legion::Events`

## [1.4.10] - 2026-03-24

### Added
- `Legion::Crypt.delete(path)` for Vault KV path deletion (supports credential revocation on worker termination)

## [1.4.9] - 2026-03-22

### Added
- `Legion::Crypt::Helper` module: injectable Vault mixin for LEX extensions
- Namespaced `vault_get`, `vault_write`, `vault_exist?` with automatic lex-prefixed paths

## [1.4.8] - 2026-03-22

### Changed
- Added logging to all silent rescue blocks across attestation, cluster_secret, ed25519, erasure, jwks_client, ldap_auth, vault_jwt_auth, and vault_kerberos_auth

## [1.4.7] - 2026-03-22

### Added
- Logging across vault, JWT, JWKS, Ed25519, PartitionKeys, Attestation, LdapAuth, VaultJwtAuth, VaultCluster operations
- `vault.rb`: `.info` on Vault connect, `.info` on cluster token renewal, `.debug` on read/write/get paths, `.warn` on read/write/get failures, `.debug` on renewal cycle start/complete
- `jwt.rb`: `.info` on JWT issue (subject, expiry, algorithm), `.debug` on verify success, `.warn` on verify failures (expired, invalid, decode) before raising
- `jwks_client.rb`: `.debug` on JWKS fetch URL, `.debug` on cache hit, `.warn` on fetch failure
- `ed25519.rb`: `.debug` on keypair generation, sign, verify, and Vault store/load paths
- `partition_keys.rb`: `.debug` on key derivation, `.warn` on encrypt/decrypt failures
- `attestation.rb`: `.debug` on attestation create/verify, `.warn` on verification failure
- `ldap_auth.rb`: `.info` on LDAP login success, `.warn` on LDAP login failure
- `vault_jwt_auth.rb`: `.warn` on JWT auth client/server errors in non-bang `login`
- `vault_cluster.rb`: `.info` on successful cluster connect

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
