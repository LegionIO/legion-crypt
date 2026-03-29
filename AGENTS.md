# legion-crypt Agent Notes

## Scope

`legion-crypt` handles cryptography and secret workflows for Legion: cipher ops, Vault integration, JWT/JWKS verification, key lifecycle, mTLS, and lease/token renewers.

## Fast Start

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## Primary Entry Points

- `lib/legion/crypt.rb`
- `lib/legion/crypt/cipher.rb`
- `lib/legion/crypt/jwt.rb`
- `lib/legion/crypt/jwks_client.rb`
- `lib/legion/crypt/vault.rb`
- `lib/legion/crypt/lease_manager.rb`
- `lib/legion/crypt/token_renewer.rb`
- `lib/legion/crypt/mtls.rb`

## Guardrails

- Treat all changes as security-sensitive. Never log secrets, tokens, private keys, or decrypted plaintext.
- Preserve JWT behavior across HS256/RS256 and external JWKS validation.
- Keep Vault-dependent logic optional and safely guarded for environments without Vault.
- Background renewal/rotation threads must stop cleanly on shutdown and handle failure with bounded retry.
- Maintain compatibility for Kerberos, LDAP, and JWT Vault auth paths.
- Cryptographic defaults and key lifecycle behavior are contract-sensitive; change only with test coverage.

## Validation

- Run targeted specs for changed auth/crypto paths first.
- Before handoff, run full `bundle exec rspec` and `bundle exec rubocop`.
