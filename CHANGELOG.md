# Legion::Crypt

## [Unreleased]

## [1.5.9] - 2026-04-10

### Fixed
- Vault lease cascade revocation: all three service credentials (RabbitMQ, PostgreSQL, Redis) died at exactly 2 hours when the Vault Kerberos auth token expired — Vault cascade-revokes all child leases when the parent token dies, regardless of individual lease TTLs (closes #29)
- `TokenRenewer` now detects non-renewable tokens (`renewable=false`) and skips `renew_self` (which always fails for non-renewable tokens), going straight to `reauth_kerberos` before the token expires
- `TokenRenewer#reauth_kerberos` now triggers `LeaseManager.reissue_all` after obtaining a new token, re-issuing all active leases under the new token so they are not orphaned when the old token expires
- `LeaseManager#push_to_settings` symbol/string key mismatch: `resolve_secrets!` registers refs with string keys (`"rabbitmq"`) via `lease://` URI parsing, but `cache_lease` stores leases with symbol keys (`:rabbitmq` from `Legion::JSON.load`) — now tries both key types
- `LeaseManager#trigger_reconnect` for `:postgresql` — uses surgical Sequel pool `disconnect` + `test_connection` instead of `Data.shutdown + Data.setup` which tore down unrelated connections (Apollo SQLite, Local cache)
- `LeaseManager#trigger_reconnect` for `:redis` — uses `Cache.restart` (the actual method) instead of `Cache.reconnect` (which does not exist)

### Added
- `LeaseManager#reissue_all` — re-issues all active leases under the current vault client token; called by `TokenRenewer` after successful Kerberos re-authentication to prevent cascade revocation of orphaned leases

## [1.5.8] - 2026-04-09

### Added
- Configurable SSL verification for Vault connections via `crypt.vault.tls.verify` setting (`peer`/`none`/`mutual`, defaults to `peer`)
- Global Vault client (`vault.rb`) now sets `::Vault.ssl_verify` from `vault.tls.verify` setting
- Per-cluster Vault clients (`vault_cluster.rb`) now pass `ssl_verify:` to `::Vault::Client.new` from `config[:tls][:verify]`
- JWKS client (`jwks_client.rb`) now sets `Net::HTTP#verify_mode` from `crypt.jwt.jwks_tls_verify` setting (`peer`/`none`, defaults to `peer`)
- `jwks_tls_verify: 'peer'` default added to JWT settings
- `tls: { verify: 'peer' }` default added to Vault settings

## [1.5.7] - 2026-04-08

### Fixed
- `LeaseManager#cache_lease` now stores the `:path` from static lease definitions, enabling `reissue_lease` fallback when `sys.renew` fails or leases hit max_ttl — previously static leases (configured via `crypt.vault.leases`) would silently expire after their TTL with no recovery (fixes #28)
- `LeaseManager#renew_lease` now logs a warning and falls back to reissue when the path is available, or warns explicitly when no path is available — previously renewal failures for pathless leases were silent

### Added
- `LeaseManager#trigger_reconnect(name)` — dispatches reconnect to the appropriate service after credential reissue: `:rabbitmq` → `Transport::Connection.force_reconnect`, `:postgresql` → `Data.reconnect`, `:redis` → `Cache.reconnect`; all guarded with `defined?`/`respond_to?` and rescue-safe
- Comprehensive INFO/WARN logging across the entire lease lifecycle:
  - INFO on lease fetch attempt, fetch success (with lease_id/ttl/renewable), renewal attempt, renewal success (with new_ttl), reissue attempt, reissue success (with new_lease_id/ttl), approaching expiry detection (with remaining/renewable/has_path), credentials changed during renewal, reconnect triggered, renewal loop start/exit
  - WARN on non-renewable lease with no reissue path, renewal failure with no reissue path, reissue returning no data, reconnect failure, cannot reissue due to missing path

### Changed
- `LeaseManager#reissue_lease` now calls `trigger_reconnect(name)` instead of inline `:rabbitmq`-only `force_reconnect`, extending credential rotation reconnect support to PostgreSQL and Redis

## [1.5.6] - 2026-04-07

### Added
- `VaultEntity` module (`lib/legion/crypt/vault_entity.rb`) — Phase 7 Vault identity tracking
  - `ensure_entity(principal_id:, canonical_name:, metadata: {})` — creates or finds a Vault entity for a Legion principal; entity names are prefixed with `legion-` to avoid collision; metadata includes `legion_principal_id`, `legion_canonical_name`, and `managed_by: 'legion'`; returns entity ID string or nil on failure (non-fatal)
  - `ensure_alias(entity_id:, mount_accessor:, alias_name:)` — creates an entity alias linking an auth method mount to the entity; idempotent (`already exists` HTTPClientError is swallowed); all other `Vault::HTTPClientError` responses log warn and return nil (non-fatal)
  - `find_by_name(canonical_name)` — looks up a Vault entity by its Legion canonical name via `identity/entity/name/legion-{name}`; returns entity ID or nil
  - All operations are non-fatal — rescue and log warn on failure; boot/request flow is never blocked by entity tracking errors
  - Delegates Vault API calls to `LeaseManager.instance.vault_logical` (public delegator) when available; falls back to `::Vault.logical`

## [1.5.5] - 2026-04-07

### Added
- `RMQ_ROLE_MAP` constant mapping `:agent`/`:infra` → `'legionio-infra'` and `:worker` → `'legionio-worker'` for Vault RabbitMQ role selection (Phase 5 credential scoping)
- `dynamic_rmq_creds?` helper reads `Settings[:crypt][:vault][:dynamic_rmq_creds]` flag
- `fetch_bootstrap_rmq_creds` — fetches short-lived bootstrap RabbitMQ credentials from `rabbitmq/creds/legionio-bootstrap` and writes them to `Settings[:transport][:connection]`; gated on `vault_connected? && dynamic_rmq_creds?`; stores `@bootstrap_lease_id` for later revocation; rescue-safe
- `swap_to_identity_creds(mode:)` — fetches identity-scoped RabbitMQ credentials from the role matching `mode`, registers them with `LeaseManager` for renewal, updates transport settings, calls `Transport::Connection.force_reconnect`, and revokes the bootstrap lease; raises if reconnect fails (before revoking bootstrap)
- `revoke_bootstrap_lease` — revokes `@bootstrap_lease_id` via `LeaseManager#vault_sys`; non-fatal on failure; idempotent
- `LeaseManager#register_dynamic_lease` — registers a dynamically-fetched Vault lease into the cache and active lease tracking with mutex, stores `path` for `reissue_lease`, registers settings refs for rotation push-back
- `LeaseManager#reissue_lease(name)` — performs a full re-read (`logical.read(path)`) at credential rotation time, updates cache + active_leases in mutex, calls `push_to_settings`, triggers `Transport::Connection.force_reconnect` for `:rabbitmq` leases
- `LeaseManager#vault_logical` and `LeaseManager#vault_sys` — public delegators to the private `logical`/`sys` methods for use by `Crypt` bootstrap/swap operations
- `dynamic_rmq_creds: false` and `dynamic_pg_creds: false` defaults added to vault settings

### Changed
- `start_lease_manager` now starts the renewal thread when `dynamic_rmq_creds: true` even if no static leases are configured, ensuring the renewal loop is running before identity-scoped leases are registered post-boot

## [1.5.4] - 2026-04-06

### Added
- `JWT.issue_identity_token` — convenience method wrapping `JWT.issue` with identity claims from `Identity::Process` (Wire Format Phase 3); accepts `issuer:` kwarg (defaults to `'legion'`) passed through to `JWT.issue`; normalizes and rejects conflicting string-keyed extra claims before merging

## [1.5.3] - 2026-04-06

### Added
- `JwksClient.prefetch!(url)` — fire-and-forget JWKS key fetch in background thread
- `JwksClient.start_background_refresh!(url, interval:)` — `Concurrent::TimerTask` for hourly key refresh
- `JwksClient.stop_background_refresh!` — stops background refresh timer task
- `bootstrap_lease_ttl: 300` in vault defaults (5-minute TTL for bootstrap credentials)

### Changed
- `JwksClient.clear_cache` now also stops any running background refresh task

## [1.5.2] - 2026-04-03

### Fixed
- LeaseManager `at_exit` hook now wraps shutdown in a 10s timeout to prevent process hang when Logger Monitor or network I/O is blocked during crash exit

## [1.5.1] - 2026-04-03

### Fixed
- Vault `read` method no longer prepends a `legion/` mount prefix to paths — the default `type` parameter changed from `'legion'` to `nil` to match the actual KV v2 mount path in the `legionio` namespace
- LeaseManager now registers an `at_exit` hook to revoke active Vault leases on unclean process exit, preventing orphaned dynamic credentials (RabbitMQ users, PostgreSQL roles, Redis creds)

## [1.5.0] - 2026-04-02

### Fixed
- Cluster-secret Vault synchronization now uses the documented `push_cluster_secret` setting, stores the new secret before pushing it, aligns Vault read/write path and field names, and invalidates cached derived key material on rotation
- External JWT/JWKS verification now fails closed on missing issuer or audience expectations, keeps reserved claims library-controlled, requires HTTPS JWKS transport, and avoids repeated fresh-cache re-fetches for unknown `kid` values
- Shared symmetric encryption now emits authenticated AES-256-GCM payloads for new ciphertexts while preserving decrypt compatibility with legacy AES-256-CBC payloads
- RSA keypair helper encryption now uses explicit OAEP padding for new ciphertexts while preserving decrypt compatibility with legacy PKCS#1 v1.5 payloads
- Multi-cluster Vault auth and helper routing now update live LDAP client tokens, keep per-cluster LDAP state local to the addressed cluster, sync the top-level Vault connected flag from cluster connectivity checks, allow explicit cluster-targeted helper calls, refresh lease metadata on renewal, and schedule short-lived token renewals before expiry
- SPIFFE X.509 fetch now fails closed by default, uses an explicit `allow_x509_fallback` development switch for self-signed fallback SVIDs, tags returned SVIDs with their source, and sends a valid 9-byte HTTP/2 SETTINGS frame during Workload API connection setup
- Ed25519 helper key persistence now uses the supported `Legion::Crypt` API with normalized KV paths, and tenant erasure verification no longer reports success when Vault access itself failed
- Background worker lifecycle is now serialized and cooperative: repeated `Legion::Crypt.start` calls no longer spawn duplicate workers, renewal/rotation threads no longer use `Thread#kill`, and timed-out joins keep their live thread references instead of dropping them

### Changed
- Adopted `Legion::Logging::Helper` across `lib/` so library logs use structured component tagging instead of direct `Legion::Logging.*` calls
- Expanded `info`/`debug`/`error` coverage across crypt, Vault, JWT, lease, mTLS, SPIFFE, and auth flows to make background actions and failures visible without exposing secrets
- Replaced manual rescue logging with `handle_exception(...)` across library code paths and left Sinatra/API integration untouched for a later pass
- Removed remaining `log_info`/`log_warn`/`log_debug` wrapper methods in `lib/` so helper-backed logging is used directly throughout the library

### Added
- Runtime dependency on `legion-logging`
- Compatibility shim for `Legion::Logging::Helper` so `handle_exception` and shared `log` access are available consistently during the uplift

## [1.4.29] - 2026-03-31

### Changed
- `force_cluster_secret` and `settings_push_vault` default to `false` instead of always returning `true`
- Default settings: `push_cluster_secret` and `read_cluster_secret` now default to `false`
- Both methods now use `fetch` with explicit default, fixing `|| true` bug that made the settings impossible to disable

## [1.4.28] - 2026-03-31

### Fixed
- `Helper#vault_write` now accepts keyword args (`**data`) and splats to `Crypt.write`, fixing `ArgumentError` on Ruby 3.4 when writing to Vault KV

## [1.4.27] - 2026-03-31

### Fixed
- `connect_vault` now sets `::Vault.namespace` from `vault_namespace` setting, fixing 403 errors for non-cluster Vault connections in namespaced environments
- Extracted `resolve_vault_address` and `log_vault_connection_error` to reduce `connect_vault` complexity

## [1.4.26] - 2026-03-28

### Fixed
- `push_cs_to_vault` now rescues `StandardError` and returns `false` instead of propagating Vault errors (e.g. 403 permission denied), ensuring `set_cluster_secret` always stores the cluster secret in Settings even when the Vault write fails

### Added
- Specs for `push_cs_to_vault` rescue path: verifies the method returns false and does not raise on Vault errors, and logs a warning when `Legion::Logging` is available
- Specs for `set_cluster_secret` confirming Settings assignment completes when Vault push returns false

## [1.4.25] - 2026-03-28

### Fixed
- `kv_client` and `logical_client` now route through the default cluster `Vault::Client` when multi-cluster is configured, preventing 403 errors caused by the un-initialized global `::Vault` singleton (closes #1)
- `WorkloadApiClient#decode_varint`: returns `[value, bytes_consumed]` correctly; previous implementation returned `[value, start_pos]` causing the protobuf field scanner to never advance past the first tag, breaking `extract_proto_field` for any non-empty input
- `WorkloadApiClient#self_signed_fallback`: Subject CN is now a plain string (`legion-fallback-svid`) instead of the full `spiffe://` URI, preventing `TypeError: no implicit conversion of nil into String` from `OpenSSL::X509::Name.parse` on Ruby 3.4
- `spiffe_identity_helpers_spec.rb`: test cert helper uses plain CN for the same reason

### Added
- Specs for `kv_client`/`logical_client` routing: 20 examples covering multi-cluster path (cluster client used, global singleton not touched) and single-server fallback path (global singleton used, `vault_client` not called) for `get`, `write`, `exist?`, `delete`, and `read` methods
- SPIFFE/SVID support implementing GitHub issue #8: `Spiffe::WorkloadApiClient` (Unix-domain gRPC for x509/JWT SVIDs with self-signed fallback), `Spiffe::SvidRotation` (background renewal at configurable window), `Spiffe::IdentityHelpers` mixin (sign/verify/extract/trust helpers); wired into `Crypt.start`/`shutdown` behind `spiffe.enabled: false` feature flag
- `spiffe` default settings block with `enabled`, `socket_path`, `trust_domain`, `workload_id`, `renewal_window`
- 82 specs covering SPIFFE ID parsing, SVID lifecycle, Workload API client (with mocked socket), self-signed fallback, protobuf field decoding, signing/verification, SAN extraction, and trust chain validation (closes #8)

## [1.4.24] - 2026-03-28

### Fixed
- `LeaseManager#start`: no longer creates new Vault dynamic credentials when a valid cached lease already exists, preventing orphaned RabbitMQ users on repeated `start` calls (closes #6)
- `LeaseManager#start`: expired leases are now revoked before re-fetching, ensuring clean credential rotation

### Added
- `LeaseManager#lease_valid?`: returns true when a named lease is cached and its `expires_at` is in the future
- `LeaseManager#revoke_expired_lease`: revokes and clears a stale cached lease entry before a re-fetch
- Specs for repeated `start` idempotency, expired-lease re-fetch, `lease_valid?` edge cases

## [1.4.23] - 2026-03-27

### Fixed
- `connect_vault` now accepts Vault standby responses (429, 472, 473) as healthy, fixing connection failures against performance standby nodes
- `connect_all_clusters` uses the same standby-tolerant health check

## [1.4.22] - 2026-03-27

### Changed
- Replace split `log.error(e.message); log.error(e.backtrace)` patterns with single `Legion::Logging.log_exception` calls in `vault.rb`, `cluster_secret.rb`, and `settings.rb` for structured exception events
- Guard all `log_exception` call sites in `vault.rb`, `settings.rb`, and `cluster_secret.rb` with `Legion::Logging` presence checks (`defined?` in `vault.rb`/`cluster_secret.rb`, `Legion.const_defined?('Logging')` in `settings.rb`) plus `Legion::Logging.respond_to?(:log_exception)`; fall back to `Legion::Logging.fatal`/`error` or `warn` to preserve structured logging in environments where `log_exception` is unavailable
- `from_transport` and `cs` rescue blocks in `cluster_secret.rb` now use the same 4-branch guard (log_exception / Logging.error / Logging.warn / Kernel.warn) and explicitly return `nil` to preserve expected return types
- Fallback `.error`/`.warn`/`Kernel.warn` branches in `from_transport` and `cs` include the first 10 backtrace lines for debuggability parity with the prior `e.backtrace[0..10]` logging; `Vault#connect_vault` warn fallback omits backtrace to keep health-check failure messages concise
- `cs` rescue adds final `Kernel.warn` fallback so exceptions are never silently swallowed when `Legion::Logging` is absent

### Added
- Specs for `connect_vault` rescue logging: asserts `false` return and covers log_exception / Logging.error / warn fallback branches when `Vault.sys.health_status` raises
- Specs for `from_transport` and `cs` rescue paths: asserts `nil` return and covers all logging fallback branches (including `Kernel.warn`) plus `Legion::Logging` absent case
- Duplicate invocation eliminated in rescue-path specs: single call stored in `result`, both no-raise and return value asserted on that one call

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
