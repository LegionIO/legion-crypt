# legion-crypt: Encryption and Vault Integration for LegionIO

**Repository Level 3 Documentation**
- **Parent**: `/Users/miverso2/rubymine/legion/CLAUDE.md`

## Purpose

Handles encryption, decryption, secrets management, JWT token management, and HashiCorp Vault connectivity for the LegionIO framework. Provides AES-256-CBC message encryption, RSA key pair generation, cluster secret management, JWT issue/verify operations, and Vault token lifecycle management.

**GitHub**: https://github.com/LegionIO/legion-crypt
**License**: Apache-2.0

## Architecture

```
Legion::Crypt (singleton module)
├── .start             # Initialize: generate keys, connect to Vault
├── .encrypt(string)   # AES-256-CBC encryption
├── .decrypt(message)  # AES-256-CBC decryption
├── .shutdown          # Stop Vault renewer, close sessions
│
├── Cipher             # OpenSSL cipher operations (AES-256-CBC)
│   ├── .encrypt       # Encrypt with cluster secret
│   ├── .decrypt       # Decrypt with cluster secret
│   ├── .private_key   # RSA private key (generated or loaded)
│   └── .public_key    # RSA public key
│
├── Vault              # HashiCorp Vault integration
│   ├── .connect_vault # Establish Vault session
│   ├── .read(path)    # Read secret from Vault
│   ├── .write(path)   # Write secret to Vault
│   └── .renew_token   # Token renewal
│
├── JWT                # JSON Web Token operations
│   ├── .issue         # Create signed JWT (HS256 or RS256)
│   ├── .verify        # Verify and decode JWT
│   ├── .verify_with_jwks  # Verify RS256 token via external JWKS endpoint (Entra ID, etc.)
│   └── .decode        # Decode without verification (inspection)
│
├── JwksClient         # External JWKS endpoint integration (thread-safe)
│   ├── .fetch_keys    # Fetch and parse JWKS from a URL
│   ├── .find_key      # Lookup key by kid (cache-first, re-fetch on miss)
│   └── .clear_cache   # Clear the key cache
│
├── ClusterSecret      # Cluster-wide shared secret management
│   └── .cs            # Generate/distribute cluster secret
│
├── VaultJwtAuth       # Vault JWT auth backend integration
│   ├── .login         # Authenticate to Vault using a JWT token, returns Vault token hash
│   ├── .login!        # Authenticate and set ::Vault.token for subsequent operations
│   └── .worker_login  # Issue a Legion JWT and authenticate to Vault in one step
│
├── VaultRenewer       # Background Vault token renewal thread
├── Ed25519            # Ed25519 key generation, signing, verification, Vault storage
├── PartitionKeys      # HKDF per-tenant key derivation, AES-256-GCM encrypt/decrypt
├── Erasure            # Cryptographic erasure via Vault master key deletion
├── Attestation        # Signed identity claims with Ed25519, freshness checking
├── LeaseManager       # Dynamic Vault lease lifecycle: fetch, cache, renew, rotate, push-back
├── MockVault          # In-memory Vault mock for local development mode
├── Settings           # Default crypt config
└── Version
```

### Key Design Patterns

- **Dynamic Keys**: By default, generates new RSA key pair per process start (no persistent keys)
- **Cluster Secret**: Shared AES key distributed across Legion nodes for inter-node encrypted communication
- **Vault Conditional**: Vault module is only included if the `vault` gem is available
- **Token Lifecycle**: VaultRenewer runs background thread for automatic token renewal
- **JWT Dual Algorithm**: HS256 (symmetric, cluster secret) for intra-cluster tokens; RS256 (asymmetric, RSA keypair) for tokens verifiable without sharing the signing key
- **JWKS External Validation**: `JwksClient` fetches public keys from external identity provider JWKS endpoints (Entra ID, Bot Framework). Keys cached for 1 hour (CACHE_TTL=3600s), thread-safe via Mutex, automatic re-fetch on cache miss handles key rotation

## Default Settings

```json
{
  "vault": { "..." : "see vault settings" },
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

## Dependencies

| Gem | Purpose |
|-----|---------|
| `ed25519` (~> 1.3) | Ed25519 key operations (pure Ruby) |
| `jwt` (>= 2.7) | JSON Web Token encoding/decoding |
| `vault` (>= 0.17) | HashiCorp Vault Ruby client |

Dev dependencies: `legion-logging`, `legion-settings`

## File Map

| Path | Purpose |
|------|---------|
| `lib/legion/crypt.rb` | Module entry, start/shutdown lifecycle |
| `lib/legion/crypt/cipher.rb` | AES-256-CBC encrypt/decrypt, RSA key generation |
| `lib/legion/crypt/jwt.rb` | JWT issue/verify/decode/verify_with_jwks operations |
| `lib/legion/crypt/jwks_client.rb` | JWKS endpoint fetch, parse, cache (thread-safe, 1hr TTL) |
| `lib/legion/crypt/vault.rb` | Vault read/write/connect/renew operations |
| `lib/legion/crypt/cluster_secret.rb` | Cluster-wide shared secret management |
| `lib/legion/crypt/vault_jwt_auth.rb` | Vault JWT auth backend: `.login`, `.login!`, `.worker_login`; raises `AuthError` on failure |
| `lib/legion/crypt/vault_renewer.rb` | Background Vault token renewal |
| `lib/legion/crypt/lease_manager.rb` | Dynamic Vault lease lifecycle management |
| `lib/legion/crypt/settings.rb` | Default configuration |
| `lib/legion/crypt/ed25519.rb` | Ed25519 key generation, signing, verification, Vault storage |
| `lib/legion/crypt/partition_keys.rb` | HKDF per-tenant key derivation with AES-256-GCM |
| `lib/legion/crypt/erasure.rb` | Cryptographic erasure via Vault master key deletion |
| `lib/legion/crypt/attestation.rb` | Signed identity claims with Ed25519 signatures |
| `lib/legion/crypt/version.rb` | VERSION constant |

## Role in LegionIO

First service-level module initialized during `Legion::Service` startup (before transport). Provides:
1. Vault token for `legion-transport` to fetch RabbitMQ credentials
2. Message encryption for `legion-transport` (optional `transport.messages.encrypt`)
3. Cluster secret for inter-node encrypted communication
4. JWT tokens for node authentication and task authorization
5. External token verification for identity providers (Entra ID OIDC via JWKS)

### Vault JWT Auth Usage

```ruby
# Authenticate to Vault using a JWT (Vault must have JWT auth method enabled)
result = Legion::Crypt::VaultJwtAuth.login(jwt: token, role: 'legion-worker')
# => { token: '...', lease_duration: 3600, renewable: true, policies: [...], metadata: {} }

# Authenticate and set Vault client token in one step
Legion::Crypt::VaultJwtAuth.login!(jwt: token)

# Issue a Legion JWT and use it to authenticate to Vault (convenience for workers)
result = Legion::Crypt::VaultJwtAuth.worker_login(worker_id: 'abc', owner_msid: 'user@example.com')
```

Vault prerequisites: `vault auth enable jwt` + configure `auth/jwt/config` with JWKS URL or bound issuer.

### JWT Usage

```ruby
# Convenience methods (auto-selects keys from settings)
token = Legion::Crypt.issue_token({ node_id: 'abc' }, ttl: 3600)
claims = Legion::Crypt.verify_token(token)

# Direct module usage (explicit keys)
token = Legion::Crypt::JWT.issue(payload, signing_key: key, algorithm: 'RS256')
claims = Legion::Crypt::JWT.verify(token, verification_key: pub_key, algorithm: 'RS256')
decoded = Legion::Crypt::JWT.decode(token) # no verification, inspection only
```

**Algorithms:**
- `HS256` (default): Uses cluster secret. All cluster nodes can issue and verify.
- `RS256`: Uses RSA keypair. Only the issuing node can sign; anyone with the public key can verify.

### External Token Verification (JWKS)

Verify tokens from external identity providers using their public JWKS endpoints:

```ruby
# Convenience method
claims = Legion::Crypt.verify_external_token(
  token,
  jwks_url: 'https://login.microsoftonline.com/TENANT/discovery/v2.0/keys',
  issuers:  ['https://login.microsoftonline.com/TENANT/v2.0'],
  audience: 'app-client-id'
)

# Direct module usage
claims = Legion::Crypt::JWT.verify_with_jwks(token, jwks_url: jwks_url)
```

**Flow:** decode JWT header (unverified) to extract `kid` -> `JwksClient.find_key` fetches the matching public key from cache or JWKS endpoint -> verify JWT signature with the public key.

**Options:** `issuers:` (array, multi-issuer support), `audience:` (string), `verify_expiration:` (bool, default true).

**Error hierarchy:** `ExpiredTokenError`, `InvalidTokenError` (bad signature, wrong issuer, wrong audience), `DecodeError` (malformed token) — all inherit from `Legion::Crypt::JWT::Error`.

**Used by:** `lex-identity` Entra runner for Digital Worker OIDC token validation.

---

**Maintained By**: Matthew Iverson (@Esity)
