# legion-crypt

Encryption, secrets management, JWT token management, and HashiCorp Vault integration for the [LegionIO](https://github.com/LegionIO/LegionIO) framework. Provides AES-256-GCM message encryption with legacy AES-256-CBC decryption, RSA key pair generation, cluster secret management, JWT issue/verify operations, Vault token lifecycle management, and multi-cluster Vault connectivity.

## Installation

```bash
gem install legion-crypt
```

Or add to your Gemfile:

```ruby
gem 'legion-crypt'
```

## Usage

```ruby
require 'legion/crypt'

Legion::Crypt.start
encrypted = Legion::Crypt.encrypt('this is my string')
Legion::Crypt.decrypt(encrypted[:enciphered_message], encrypted[:iv])
```

Authenticated ciphertext requires a full 16-byte GCM tag. Saved RSA private keys are created with `0600` permissions; existing files are restricted before writing.

`Legion::Crypt.start(mode: nil, **)` accepts extra keyword context. With `mode: :infra`, an existing PostgreSQL lease uses `postgresql/creds/infra` without mutating its configured path; other modes preserve the configured path. The mode-to-role mapping is a fixed framework convention, not an operator setting.

Vault connectivity inspection propagates errors rather than reporting broken configuration as disconnected. Startup orchestration and bootstrap credential handling recover only from their declared operational failures, using `handle_exception` at warning level; programming errors propagate to callers.

### Cluster secret readiness

Discovery checks settings, Vault, and then peers. Random generation requires confirmed empty-cluster membership, the lite transport adapter, or standalone operation (no transport loaded or transport explicitly disabled). Disconnected or unknown cluster membership does not authorize a competing key.

`crypt.cluster_secret_timeout` bounds initialization (default: 5 seconds; finite and positive). `crypt.cluster_length` must be a positive integer (default: 32 bytes). Invalid secrets, discovery failures, and shutdown cancellation raise `Legion::Crypt::ClusterSecret::InitializationError`; encryption and decryption do not proceed with a missing key.

Use `Legion::Crypt.set_cluster_secret(secret)` to validate and install a received secret. Derived keys also detect settings replacement or mutation, so reloads cannot continue using the previous secret.

### JWT Tokens

```ruby
# Issue a token (defaults to HS256 using cluster secret)
token = Legion::Crypt.issue_token({ node_id: 'abc' }, ttl: 3600)

# Verify and decode a token
claims = Legion::Crypt.verify_token(token)

# Use RS256 (RSA keypair) instead
token = Legion::Crypt.issue_token({ node_id: 'abc' }, algorithm: 'RS256')
claims = Legion::Crypt.verify_token(token, algorithm: 'RS256')

# Inspect a token without verification
decoded = Legion::Crypt::JWT.decode(token)
```

### External Token Verification (JWKS)

Verify tokens from external identity providers (Entra ID, Bot Framework) using their public JWKS endpoints:

```ruby
# Verify an Entra ID OIDC token
claims = Legion::Crypt.verify_external_token(
  token,
  jwks_url: 'https://login.microsoftonline.com/TENANT/discovery/v2.0/keys',
  issuers:  ['https://login.microsoftonline.com/TENANT/v2.0'],
  audience: 'app-client-id'
)

# Or use the JWT module directly
claims = Legion::Crypt::JWT.verify_with_jwks(token, jwks_url: jwks_url, issuers: issuers, audience: audience)
```

Public keys are cached for 1 hour. Concurrent misses for one URL share a refresh. The first unknown key ID triggers an immediate rotation check; subsequent missing-key lookups are throttled for 30 seconds per URL. Failed upstream lookups share the same cooldown, while still-valid cached keys remain usable. Expired caches and explicit `fetch_keys` calls refresh normally.

## Configuration

Crypt requires `legion-settings` >= 1.4.2. Requiring `legion/crypt` registers its defaults once; runtime reads use the live `Legion::Settings[:crypt]` tree, including replacement trees and request overlays. The partial configuration example below shows the `crypt` section; `lib/legion/crypt/settings.rb` is the authoritative source for all defaults. Configure it through `Legion::Settings`, not the removed `Legion::Crypt.settings`, `.vault_settings`, or `.jwt_settings` accessors. `VAULT_DEV_ROOT_TOKEN_ID` and `VAULT_TOKEN_ID` provide boot defaults; they do not overwrite an explicit live Vault token.

`crypt.mtls` owns the mTLS defaults registered by this gem. Certificate issuance reads `Legion::Settings[:crypt][:mtls][:vault_pki_path]` directly; the `Legion::Crypt::Mtls.pki_path` accessor is removed. `security.spiffe` remains Core-owned optional configuration with its existing absent-field defaults. Explicit false policy is never replaced by a truthy fallback. Renewal windows must be finite numbers from zero (inclusive) to one (exclusive).

After an explicit full `Legion::Settings.reset!`, standalone callers and tests must bootstrap again with `Legion::Settings.register_library(:crypt, Legion::Crypt::Settings.default)` before using configured crypto APIs. Runtime reads do not repair missing registration. Lease binding transactions and credential publication continue to mutate their intended raw settings roots, not request-overlay copies.

```json
{
  "vault": {
    "enabled": true,
    "protocol": "http",
    "address": "localhost",
    "port": 8200,
    "token": null,
    "connected": false,
    "renewer_time": 5,
    "renewer": true,
    "operation_timeout": 5,
    "push_cluster_secret": false,
    "read_cluster_secret": false,
    "kv_path": "legion",
    "leases": {}
  },
  "jwt": {
    "enabled": true,
    "default_algorithm": "HS256",
    "default_ttl": 3600,
    "issuer": "legion",
    "verify_expiration": true,
    "verify_issuer": true
  },
  "mtls": {
    "enabled": false,
    "vault_pki_path": "pki/issue/legion-internal",
    "cert_ttl": "24h",
    "renewal_window": 0.5
  },
  "cs_encrypt_ready": false,
  "dynamic_keys": true,
  "cluster_secret": null,
  "save_private_key": true,
  "read_private_key": true
}
```

### JWT Algorithms

| Algorithm | Key | Use Case |
|-----------|-----|----------|
| `HS256` (default) | Cluster secret (symmetric) | Intra-cluster tokens — all nodes can issue and verify |
| `RS256` | RSA key pair (asymmetric) | Tokens verifiable by external services without sharing the signing key |

### Vault Integration

When `vault.token` is set (or via `VAULT_TOKEN_ID` env var), Crypt connects to Vault on `start`. Vault requests use the core-owned `Legion::Crypt::Vault::Client`, built on Faraday and `Legion::JSON`; neither vault-ruby nor a LEX extension is required. Responses have symbol keys, including with JSON 3.

`Legion::Crypt.vault_client` returns the cached default client; pass a cluster name for an explicit client. Its logical, KV, and lease endpoints use keyword arguments and ignore extra keywords while still enforcing required arguments:

```ruby
client = Legion::Crypt.vault_client
lease = client.logical.read(path: 'database/creds/application')
lease.data # symbol-keyed credentials
client.sys.renew(lease_id: lease.lease_id)
client.kv(mount: 'legion').write(path: 'application', data: { enabled: true })
```

The existing `Legion::Crypt.read`, `get`, `write`, and `delete` interfaces are unchanged. Logical reads preserve lease metadata; KV reads unwrap the KV v2 data envelope. Missing reads return `nil`, while HTTP failures raise `Legion::Crypt::Vault::HTTPClientError` (4xx), `HTTPServerError` (5xx), or their `HTTPError` base class with a numeric `code`. Redirects are not followed.

Standalone clients accept `address:`, `token:`, `namespace:`, `timeout:`, and `tls:`. TLS uses the existing `verify: 'peer'`, `'none'`, or `'mutual'` configuration with `ca:`, `cert:`, and `key:` material. CA, certificate, and key values can be PEM or file paths; client identities also accept OpenSSL objects. `shutdown` permanently retires a client, including retained endpoint handles.

Vault-backed TLS material can resolve through another connected cluster without holding the client-cache lock. Explicit `ca`, `cert`, or `key` references that cannot resolve fail client construction rather than silently falling back to system trust or dropping the identity. Circular TLS dependencies are rejected; bootstrap the source cluster with independently available trust material.

Lease acquisition, renewal, reissue, token maintenance, and session revocation use the finite-positive `crypt.vault.operation_timeout` budget (default: 5 seconds). Failures are isolated per item. Shutdown shares a 10-second deadline, invalidates worker generations before external cleanup, and resets lifecycle state even when revocation fails. Late callbacks cannot restore credentials or settings after their lifecycle stops.

### Dynamic Vault Leases

The `LeaseManager` handles dynamic secrets from any Vault secrets engine (database, RabbitMQ, AWS, PKI, etc.). Define named leases in crypt settings — each lease maps a stable name to a Vault path:

```json
{
  "crypt": {
    "vault": {
      "leases": {
        "rabbitmq":   { "path": "rabbitmq/creds/legion-role" },
        "bedrock":    { "path": "aws/creds/bedrock-role" },
        "postgresql": { "path": "postgresql/creds/node" }
      }
    }
  }
}
```

`postgresql` is the lease name recognized by `Legion::Crypt.start(mode: :infra)` for role selection. Other lease names retain their configured paths.

Other settings files reference lease data using `lease://name#key`:

```json
{
  "transport": {
    "connection": {
      "username": "lease://rabbitmq#username",
      "password": "lease://rabbitmq#password"
    }
  }
}
```

Both `username` and `password` come from a single Vault read — one lease, one credential pair. The `LeaseManager`:

- Fetches all leases at boot (during `Crypt.start`, before `resolve_secrets!`)
- Caches response data and lease metadata
- Renews leases in the background at 50% TTL
- Detects credential rotation and pushes new values into `Legion::Settings` in-place
- Revokes all leases on `Crypt.shutdown`

Failed acquisition remains pending with exponential backoff from 1 second to a 60-second cap. Maintenance wakes for the next renewal or retry deadline (10 ms minimum, 5 seconds maximum), rather than waiting five seconds before servicing short-TTL leases.

TTL-only renewals update lease lifetime without reconnecting consumers whose credentials and settings are unchanged. A renewal that returns rotated credentials still publishes the new values and verifies the consumer reconnect before committing.

Expired leases are reacquired rather than repeatedly renewed after timeout. `fetch`, `lease_data`, settings publication and initialized counts exclude expired cached credentials, so `lease://` fallback chains can proceed during an outage. Lease ownership remains tracked for cleanup even when expired credential data is discarded.

Credential replacement installs settings and cache, confirms the required consumer reconnect, then retires the previous lease. Failed handoffs restore the previous settings and cache; old and unconfirmed candidate IDs remain owned until safe cleanup or shutdown. Failed revocations are retried, using the Vault client that issued the lease. RabbitMQ must report an open session; PostgreSQL must support and successfully complete `reconnect_with_fresh_creds`; Redis must reconnect successfully and report connected when that status is available.

Lease names are stable across environments. The actual Vault paths are deployment-specific config. `active_leases` uses Symbol names; `fetch` and `lease_data` accept either Strings or Symbols.

`LeaseManager#register_ref(name, key, path)` accepts typed destination paths: Symbols for existing Hash keys and nonnegative Integers for existing Array indexes. A lease-data key can target multiple destinations; duplicate registrations are ignored. `push_to_settings` updates valid destinations, including nested arrays, and returns the number of successful writes. Invalid, missing, frozen, or out-of-bounds destinations are not modified. Transactional credential handoff requires every referenced destination to be writable before changing any of them.

Starting with Crypt **1.5.38**, Settings **1.4.4** uses `LeaseManager#update_settings_refs(settings:, publish: nil)` to replace destination bindings and publish resolved settings atomically. Preparation runs under the lease-state mutex with a memory-only `reader.call(name:, key:)`; external secret reads must finish beforehand. The proposal contains typed `paths` to replace, `assignments` (`container`, `key`, `value`), and selected `references` (`name`, `key`, `path`, mutable `binding` containing `value`). Other destinations remain registered, and ambiguous writers are rejected.

`publish.call(proposal)` is restricted to in-memory pointer/metadata publication, not consumer callbacks or manager calls. Failed preparation, validation, or publication preserves prior assignments and bindings. Publication waits for an in-flight credential handoff to commit or roll back; successful rotations update each binding's tracked value, and failed handoffs restore both the target and its separately tracked previous value. Shutdown and reset clear bindings with the registry.

Release Crypt before Settings. Older `register_ref` callers remain supported, but source priority and reload provenance are handled by Settings, not by Crypt.

## Multi-Cluster Vault

`Legion::Crypt::Vault::Cluster` supports connecting to multiple Vault clusters simultaneously. Each cluster has its own `Legion::Crypt::Vault::Client` instance.

Clients are reused only while their endpoint, namespace, TLS verification, and token match the current configuration. Connection changes replace the cached client without disabling lease or token owners retaining its predecessor. Displaced clients are weakly tracked, so the cache does not keep unused clients alive; shutdown permanently closes all surviving clients after owner cleanup. In-place authentication token refreshes preserve the current client.

```json
{
  "crypt": {
    "vault": {
      "default": "primary",
      "clusters": {
        "primary": {
          "protocol": "https",
          "address": "vault.example.com",
          "port": 8200,
          "namespace": "my-namespace",
          "auth_method": "ldap"
        },
        "secondary": {
          "protocol": "https",
          "address": "vault2.example.com",
          "port": 8200,
          "auth_method": "ldap"
        }
      }
    }
  }
}
```

```ruby
# Authenticate to all LDAP-configured clusters at once
Legion::Crypt.ldap_login_all(username: 'user', password: 'pass')

# Read from specific cluster
Legion::Crypt.read('secret/data/mykey', cluster_name: :secondary)

# Get a Vault client for a specific cluster
client = Legion::Crypt.vault_client(:primary)
```

When `clusters` is empty, the legacy single-cluster path is used (backward compatible).

LDAP login starts token maintenance immediately, including after `Crypt.start`. Cluster state retains `lease_duration`, `renewable`, `expires_at`, and `relogin_required`; passwords are used only for the login request. Renewable tokens renew at 75% of their lifetime through the same cluster client. Transient failures retry within the remaining lifetime; nonrenewable tokens remain available until expiry. Expiry or a terminal renewal rejection marks the cluster disconnected and sets `relogin_required: true`. Authenticate again with `ldap_login` or `ldap_login_all`; LDAP never falls back to Kerberos authentication.

Repeated login stops the previous token worker before installing its replacement, and shutdown stops all token workers. With clusters configured, unavailable or expired clusters cannot fall back to the legacy global Vault client.

JWT and Kerberos `login!` use the same grant lifecycle: token, TTL, expiry, renewability and authentication strategy replace the previous state together. Existing token workers stop before publication and replacement workers use the new grant's lifetime. JWT tokens renew without Kerberos fallback; a login result completing after shutdown is rejected.

## Kerberos Authentication

When `crypt.vault.auth_method` is set to `kerberos`, `Crypt.start` performs Kerberos auto-auth to Vault using `KerberosAuth`:

```json
{
  "crypt": {
    "vault": {
      "auth_method": "kerberos",
      "kerberos": {
        "service_principal": "HTTP/vault.example.com@REALM",
        "auth_path": "auth/kerberos/login"
      }
    }
  }
}
```

The SPNEGO token is sent as an HTTP `Authorization` header (not JSON body). Kerberos auth uses the configured namespace, where the auth mount resides; configure the cluster with `"namespace": null` for a root-mounted auth method. The client namespace is not cleared or temporarily changed during authentication. Requires Homebrew MIT Kerberos (`brew install krb5`) on macOS — the system Heimdal library is not compatible.

`Legion::Crypt::TokenRenewer` renews renewable tokens at 75% TTL and retries transient failures with backoff. Only Kerberos-authenticated grants can reauthenticate through Kerberos. JWT and LDAP grants require another login after expiry or terminal rejection.

## SPIFFE Workload API

The local Unix-socket Workload API exchange has a shared 10-second monotonic deadline. Connection, HTTP/2 handshake, request writes, and flushes additionally share a 5-second setup budget; response reads use the remaining operation time. Availability probes are bounded to 5 seconds, and failed exchanges close acquired sockets.

Responses may split the gRPC prefix or body across HTTP/2 DATA frames and socket reads. JWT-SVID audiences use protobuf varint lengths, including audiences of 128 bytes or longer. X.509 fallback remains opt-in; JWT-SVID failures raise `Legion::Crypt::Spiffe::SvidError`.

## mTLS

`Legion::Crypt::Mtls` issues mTLS certificates from Vault PKI using `crypt.mtls` configuration. `issue_cert(common_name:, alt_names: '', ttl: nil, **)` preserves caller-supplied SANs and TTL overrides while accepting extra keyword context. `Legion::Crypt::CertRotation` renews at expiry minus the certificate lifetime multiplied by `crypt.mtls.renewal_window` (default `0.5`), rather than waiting for a fixed polling interval. Initial issuance and renewal failures retry with exponential backoff from 1 to 60 seconds; a failed renewal retains the last installed certificate. Shutdown interrupts scheduled waits, bounds in-flight issuance with the Vault operation timeout, and prevents late results from replacing the certificate.

`Legion::Transport::Connection::Vault` independently acquires and applies tempfile-based Bunny mTLS credentials. Certificate rotation does not itself close transport connections when a certificate expires. mTLS is disabled by default.

## Requirements

- Ruby >= 3.4
- `concurrent-ruby` (~> 1.3)
- `ed25519` (~> 1.3)
- `jwt` gem (>= 2.7)
- `faraday` gem (~> 2.0)
- `legion-json` gem (>= 1.2.0; JSON 3 supported)
- `legion-logging` (>= 1.5.0)
- `legion-settings` (>= 1.4.2)
- HashiCorp Vault (optional, for secrets management)
- `lex-kerberos` (optional, supplies the SPNEGO helper for Kerberos auth)

## Development

Use the existing checkout and the full repository checks:

```bash
bundle install
bundle exec rubocop -A
bundle exec rspec --format json --out tmp/rspec_results.json --format progress --out tmp/rspec_progress.txt
```

Run specs against the corrected code if RuboCop changes files. On failure, inspect the failing examples in `tmp/rspec_results.json`; do not substitute a narrower suite for the full check.

Specs mirror implementation paths and filenames exactly: `lib/legion/crypt/vault/client.rb` is covered by `spec/legion/crypt/vault/client.rb`, without an `_spec` suffix. Keep each spec focused on its corresponding implementation; startup, JWT convenience, and credential-scoping groups belong in `spec/legion/crypt.rb`.

`.rspec` explicitly loads `spec/spec_helper.rb` and discovers `spec/legion/**/*.rb`. The helper puts `lib/` ahead of `spec/` on Ruby's load path so production requires cannot resolve to mirrored spec files. Keep support files outside the discovered implementation-spec tree.

Require and use real gemspec dependencies rather than mocking them. `spec/spec_helper.rb` requires `legion-settings` and its resolver, isolates the settings root, and installs complete Crypt defaults for each example. The original settings state is restored afterward, including when an example replaces the loader root.

The test bundle also declares `legionio` for the legacy `Vault::Renewer` specs. Isolated Ruby subprocesses exercise the real periodic actor, cancellation lifecycle, and Vault HTTP client against a local service fixture without loading optional Core/transport components into unrelated examples. This is a development/test dependency only; Crypt's runtime gemspec does not depend on Core, and no running Vault service is required.

Set individual properties through `Legion::Settings[:crypt][...]`. For replacement-tree scenarios, start from `Legion::Crypt::Settings.default`, modify the needed nested properties, then install it with `Legion::Settings.set_prop(:crypt, configuration)`. Do not replace nested defaults with partial hashes, or stub Settings, its loader, resolver, or returned settings hashes. Keep settings changes within the example lifecycle.

Use real libraries with local service fixtures or supported test adapters for external I/O. Preserve security-sensitive behavior: test failure propagation and lifecycle transitions, never expose secrets in test output.

## License

Apache-2.0
