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

```json
{
  "vault": {
    "enabled": false,
    "protocol": "http",
    "address": "localhost",
    "port": 8200,
    "token": null,
    "connected": false,
    "renewer_time": 5,
    "renewer": true,
    "operation_timeout": 5,
    "push_cluster_secret": true,
    "read_cluster_secret": true,
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

When `vault.token` is set (or via `VAULT_TOKEN_ID` env var), Crypt connects to Vault on `start`. The background `VaultRenewer` thread keeps the token alive. Vault is an optional runtime dependency — the Vault module is only included if the `vault` gem is available.

Lease acquisition, renewal, reissue, token maintenance, and session revocation use the finite-positive `crypt.vault.operation_timeout` budget (default: 5 seconds). Failures are isolated per item. Shutdown shares a 10-second deadline, invalidates worker generations before external cleanup, and resets lifecycle state even when revocation fails. Late callbacks cannot restore credentials or settings after their lifecycle stops.

### Dynamic Vault Leases

The `LeaseManager` handles dynamic secrets from any Vault secrets engine (database, RabbitMQ, AWS, PKI, etc.). Define named leases in crypt settings — each lease maps a stable name to a Vault path:

```json
{
  "crypt": {
    "vault": {
      "leases": {
        "rabbitmq": { "path": "rabbitmq/creds/legion-role" },
        "bedrock":  { "path": "aws/creds/bedrock-role" },
        "postgres": { "path": "database/creds/apollo-rw" }
      }
    }
  }
}
```

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

Credential replacement installs settings and cache, confirms the required consumer reconnect, then retires the previous lease. Failed handoffs restore the previous settings and cache; old and unconfirmed candidate IDs remain owned until safe cleanup or shutdown. Failed revocations are retried, using the Vault client that issued the lease. RabbitMQ must report an open session; PostgreSQL must support and successfully complete `reconnect_with_fresh_creds`; Redis must reconnect successfully and report connected when that status is available.

Lease names are stable across environments. The actual Vault paths are deployment-specific config. `active_leases` uses Symbol names; `fetch` and `lease_data` accept either Strings or Symbols.

`LeaseManager#register_ref(name, key, path)` accepts typed destination paths: Symbols for existing Hash keys and nonnegative Integers for existing Array indexes. A lease-data key can target multiple destinations; duplicate registrations are ignored. `push_to_settings` updates valid destinations, including nested arrays, and returns the number of successful writes. Invalid, missing, frozen, or out-of-bounds destinations are not modified. Transactional credential handoff requires every referenced destination to be writable before changing any of them.

## Multi-Cluster Vault

`VaultCluster` supports connecting to multiple Vault clusters simultaneously. Each cluster has its own `::Vault::Client` instance.

Clients are reused only while their endpoint, namespace, TLS verification, and token match the current configuration. Connection changes retire the old client; shutdown clears and retires the cache. In-place authentication token refreshes preserve the current client.

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

## Kerberos Authentication

When `crypt.vault.auth_method` is set to `kerberos`, `Crypt.start` performs Kerberos auto-auth to Vault using `KerberosAuth`:

```ruby
# Settings
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

The SPNEGO token is sent as an HTTP `Authorization` header (not JSON body). The Vault namespace is cleared before auth (Kerberos mount is at root) and restored after. Requires Homebrew MIT Kerberos (`brew install krb5`) on macOS — the system Heimdal library is not compatible.

`TokenRenewer` keeps the Vault token alive: renews at 75% TTL, re-auths via Kerberos if renewal fails, uses exponential backoff.

## SPIFFE Workload API

The local Unix-socket Workload API exchange has a shared 10-second monotonic deadline. Connection, HTTP/2 handshake, request writes, and flushes additionally share a 5-second setup budget; response reads use the remaining operation time. Availability probes are bounded to 5 seconds, and failed exchanges close acquired sockets.

Responses may split the gRPC prefix or body across HTTP/2 DATA frames and socket reads. JWT-SVID audiences use protobuf varint lengths, including audiences of 128 bytes or longer. X.509 fallback remains opt-in; JWT-SVID failures raise `Spiffe::SvidError`.

## mTLS

`Crypt::Mtls` issues mTLS certificates from Vault PKI. When `security.mtls.enabled` is true, `Legion::Service` owns a `Crypt::CertRotation` worker. The worker renews at expiry minus the certificate lifetime multiplied by `security.mtls.renewal_window` (default `0.5`), rather than waiting for a fixed polling interval. Initial issuance and renewal failures retry with exponential backoff from 1 to 60 seconds; a failed renewal retains the last installed certificate. Shutdown interrupts scheduled waits, bounds in-flight issuance with the Vault operation timeout, and prevents late results from replacing the certificate.

`Transport::Connection::Vault` independently acquires and applies tempfile-based Bunny mTLS credentials. Certificate rotation does not itself close transport connections when a certificate expires. mTLS is disabled by default.

## Requirements

- Ruby >= 3.4
- `ed25519` (~> 1.3)
- `jwt` gem (>= 2.7)
- `vault` gem (>= 0.17, optional)
- HashiCorp Vault (optional, for secrets management)
- `gssapi` gem (optional, required for Kerberos auth)

## License

Apache-2.0
