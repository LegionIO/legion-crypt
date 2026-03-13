# legion-crypt: Encryption and Vault Integration for LegionIO

**Repository Level 3 Documentation**
- **Parent**: `/Users/miverso2/rubymine/legion/CLAUDE.md`

## Purpose

Handles encryption, decryption, secrets management, and HashiCorp Vault connectivity for the LegionIO framework. Provides AES-256-CBC message encryption, RSA key pair generation, cluster secret management, and Vault token lifecycle management.

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
├── ClusterSecret      # Cluster-wide shared secret management
│   └── .cs            # Generate/distribute cluster secret
│
├── VaultRenewer       # Background Vault token renewal thread
├── Settings           # Default crypt config
└── Version
```

### Key Design Patterns

- **Dynamic Keys**: By default, generates new RSA key pair per process start (no persistent keys)
- **Cluster Secret**: Shared AES key distributed across Legion nodes for inter-node encrypted communication
- **Vault Conditional**: Vault module is only included if the `vault` gem is available
- **Token Lifecycle**: VaultRenewer runs background thread for automatic token renewal

## Default Settings

```json
{
  "vault": {
    "enabled": false,
    "protocol": "http",
    "address": "localhost",
    "port": 8200,
    "token": null,
    "connected": false
  },
  "cs_encrypt_ready": false,
  "dynamic_keys": true,
  "cluster_secret": null,
  "save_private_key": false,
  "read_private_key": false
}
```

## Dependencies

| Gem | Purpose |
|-----|---------|
| `vault` (>= 0.15.0) | HashiCorp Vault Ruby client |

Dev dependencies: `legion-logging`, `legion-settings`

## File Map

| Path | Purpose |
|------|---------|
| `lib/legion/crypt.rb` | Module entry, start/shutdown lifecycle |
| `lib/legion/crypt/cipher.rb` | AES-256-CBC encrypt/decrypt, RSA key generation |
| `lib/legion/crypt/vault.rb` | Vault read/write/connect/renew operations |
| `lib/legion/crypt/cluster_secret.rb` | Cluster-wide shared secret management |
| `lib/legion/crypt/vault_renewer.rb` | Background Vault token renewal |
| `lib/legion/crypt/settings.rb` | Default configuration |
| `lib/legion/crypt/version.rb` | VERSION constant |

## Role in LegionIO

First service-level module initialized during `Legion::Service` startup (before transport). Provides:
1. Vault token for `legion-transport` to fetch RabbitMQ credentials
2. Message encryption for `legion-transport` (optional `transport.messages.encrypt`)
3. Cluster secret for inter-node encrypted communication

---

**Maintained By**: Matthew Iverson (@Esity)
