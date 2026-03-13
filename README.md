# legion-crypt

Encryption, secrets management, and HashiCorp Vault integration for the [LegionIO](https://github.com/LegionIO/LegionIO) framework. Provides AES-256-CBC message encryption, RSA key pair generation, cluster secret management, and Vault token lifecycle management.

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

## Configuration

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

## Requirements

- Ruby >= 3.4
- `vault` gem (>= 0.15.0)
- HashiCorp Vault (optional, for secrets management)

## License

Apache-2.0
