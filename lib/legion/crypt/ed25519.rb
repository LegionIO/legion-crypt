# frozen_string_literal: true

require 'ed25519'

module Legion
  module Crypt
    module Ed25519
      class << self
        def generate_keypair
          signing_key = ::Ed25519::SigningKey.generate
          {
            private_key:    signing_key.to_bytes,
            public_key:     signing_key.verify_key.to_bytes,
            public_key_hex: signing_key.verify_key.to_bytes.unpack1('H*')
          }
        end

        def sign(message, private_key_bytes)
          signing_key = ::Ed25519::SigningKey.new(private_key_bytes)
          signing_key.sign(message)
        end

        def verify(message, signature, public_key_bytes)
          verify_key = ::Ed25519::VerifyKey.new(public_key_bytes)
          verify_key.verify(signature, message)
          true
        rescue ::Ed25519::VerifyError
          false
        end

        def store_keypair(agent_id:, keypair: nil)
          keypair ||= generate_keypair
          vault_path = "#{key_prefix}/#{agent_id}"
          if defined?(Legion::Crypt::Vault)
            Legion::Crypt::Vault.write(vault_path, {
                                         private_key: keypair[:private_key].unpack1('H*'),
                                         public_key:  keypair[:public_key_hex]
                                       })
          end
          keypair
        end

        def load_private_key(agent_id:)
          vault_path = "#{key_prefix}/#{agent_id}"
          data = Legion::Crypt::Vault.read(vault_path)
          [data[:private_key]].pack('H*') if data&.dig(:private_key)
        rescue StandardError
          nil
        end

        private

        def key_prefix
          begin
            Legion::Settings[:crypt][:ed25519][:vault_key_prefix]
          rescue StandardError
            nil
          end || 'secret/data/legion/keys'
        end
      end
    end
  end
end
