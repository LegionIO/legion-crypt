# legion-crypt

Core encryption, secrets management, JWT, and HashiCorp Vault integration for LegionIO. Follow [LegionIO coding standards](../docs/legionio-standards.md); this file adds Crypt-specific guidance.

## Architecture

```
Legion::Crypt
├── Cipher          # AES-256-GCM encryption; legacy CBC decryption; RSA key pair
├── Vault           # read/write/connect/session renewal through VaultClient
├── VaultClient     # core-owned HTTP client using Faraday and Legion::JSON
├── VaultCluster    # client selection, caching, authentication grant publication
├── VaultOperation  # bounded operations and shared shutdown deadlines
├── JWT             # issue/verify/decode (HS256 cluster-secret or RS256 RSA)
├── JwksClient      # external JWKS endpoint, 1hr TTL cache, thread-safe
├── ClusterSecret   # shared AES key distributed across nodes
├── VaultJwtAuth    # .login / .login! / .worker_login
├── Vault::Renewer  # legacy Every actor for session renewal
├── LeaseManager    # dynamic Vault lease lifecycle
├── KerberosAuth    # SPNEGO acquisition through the optional lex-kerberos helper
├── VaultKerberosAuth # SPNEGO as Authorization header; preserves namespace
├── LdapAuth        # cluster-scoped LDAP login and token maintenance
├── TokenRenewer    # 75% TTL renewal; Kerberos-only re-auth; retry backoff
├── Ed25519         # key gen, sign, verify, Vault storage
├── PartitionKeys   # HKDF per-tenant key derivation, AES-256-GCM
├── TLS             # TLS configuration and Vault-backed material resolution
├── Mtls            # Vault PKI certificate issuance using crypt.mtls settings
├── CertRotation    # background renewal using the configured renewal window
├── Spiffe          # SPIFFE ID parse/validate, X509Svid/JwtSvid, SPIRE workload API
├── Attestation     # signed identity claims with Ed25519
├── Erasure         # cryptographic erasure via Vault master key deletion
└── MockVault       # in-memory mock for local dev
```

## Key Design Decisions

- RSA keys are memoized per process. `read_private_key` loads an existing `./legionio.key`; otherwise a key is generated. `save_private_key` persists it with owner-only permissions.
- HS256 (cluster secret) for intra-cluster tokens; RS256 (RSA keypair) for externally-verifiable tokens
- `JwksClient` caches keys for one hour, shares concurrent refreshes, and throttles repeated unknown-key refreshes.
- Vault connectivity uses the core client; the `vault` gem is not required. Kerberos SPNEGO acquisition requires the optional `lex-kerberos` helper, and authentication preserves the configured Vault namespace.
- JWT/LDAP token renewal never falls back to Kerberos. Expiry or terminal rejection requires login again; Kerberos grants alone can automatically reauthenticate.

## Framework Contracts

- Defaults live in `lib/legion/crypt/settings.rb` and are registered when `legion/crypt` is required. Core code reads `Legion::Settings[:crypt][...]` directly: no settings-only accessor wrappers, duplicated defaults, or nil guards around registered keys.
- mTLS uses `crypt.mtls`; SPIFFE still reads the optional Core-owned `security.spiffe` section. Do not treat the two settings paths as interchangeable.
- Include `Legion::Logging::Helper` explicitly in core modules/classes that need logging. Rescues must re-raise or call `handle_exception` at `:warn` or higher. Programming errors must propagate; narrow recovery to known operational failures.
- Use fully qualified Legion constants across module boundaries. New public APIs use kwargs and trailing `**`; preserve existing positional contracts unless all callers are migrated.
- Use `Legion::JSON.load` / `dump`; loaded JSON has symbol keys. Never log tokens, passwords, private keys, or decrypted plaintext.
- `start(mode: nil, **)` selects `postgresql/creds/infra` for an existing `postgresql` lease in infra mode without mutating configured leases. Fixed mode-to-role mappings remain frozen constants.
- `Legion::Crypt::Mtls.issue_cert(common_name:, alt_names: '', ttl: nil, **)` preserves explicit SAN/TTL inputs; absent TTL uses the registered default. Interface-discovery programming errors must not become loopback fallback.
- Preserve bounded shutdown, lease ownership, and generation checks: late worker results must not reinstall credentials after shutdown.

## Specs and Verification

- Require and use gemspec dependencies; do not mock them. In particular, never stub `Legion::Settings`, its loader, resolver, or returned settings hashes.
- `spec/spec_helper.rb` loads the real Settings/Resolver, isolates the settings root, installs full Crypt defaults for each example, and restores the original state afterward.
- Configure values through real bracket access or `Legion::Settings.set_prop`. Replacement Crypt configurations must retain full defaults, including nested Vault settings. Raw loader-root mutation is permitted in test setup for publication/rebuild scenarios, not as a new production access pattern.
- Prefer real libraries and local service fixtures or supported test adapters at external I/O boundaries. Cover behavior, failure propagation, and state transitions rather than forwarding calls or implementation details.

Run from this checkout:

```bash
bundle exec rubocop -A
bundle exec rspec --format json --out tmp/rspec_results.json --format progress --out tmp/rspec_progress.txt
```

Use the full suite. After lint autocorrections, verify the corrected code; read failure details from the JSON report if specs fail.

## JWT Usage

```ruby
token  = Legion::Crypt.issue_token({ node_id: 'abc' }, ttl: 3600)
claims = Legion::Crypt.verify_token(token)

# External provider (Entra ID)
claims = Legion::Crypt.verify_external_token(token,
  jwks_url: 'https://login.microsoftonline.com/TENANT/discovery/v2.0/keys',
  issuers:  ['https://login.microsoftonline.com/TENANT/v2.0'],
  audience: 'app-client-id')
```

Error hierarchy: `ExpiredTokenError`, `InvalidTokenError`, `DecodeError` — all inherit `Legion::Crypt::JWT::Error`.
