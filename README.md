# legion-crypt

Encryption, secrets management, JWT token management, and HashiCorp Vault integration for the [LegionIO](https://github.com/LegionIO/LegionIO) framework. Provides AES-256-CBC message encryption, RSA key pair generation, cluster secret management, JWT issue/verify operations, and Vault token lifecycle management.

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
Legion::Crypt.encrypt('this is my string')
Legion::Crypt.decrypt(message)
```

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
claims = Legion::Crypt::JWT.verify_with_jwks(token, jwks_url: jwks_url)
```

Public keys are cached for 1 hour and automatically re-fetched on cache miss (handles key rotation).

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

Lease names are stable across environments. The actual Vault paths are deployment-specific config.

## Requirements

- Ruby >= 3.4
- `jwt` gem (>= 2.7)
- `vault` gem (>= 0.17, optional)
- HashiCorp Vault (optional, for secrets management)

## License

Apache-2.0
