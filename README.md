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
    "kv_path": "legion"
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

## Requirements

- Ruby >= 3.4
- `jwt` gem (>= 2.7)
- `vault` gem (>= 0.17, optional)
- HashiCorp Vault (optional, for secrets management)

## License

Apache-2.0
