# frozen_string_literal: true

require 'ed25519'
require 'legion/logging/helper'

module Legion
  module Crypt
    module Ed25519
      extend Legion::Logging::Helper

      class << self
        def generate_keypair
          signing_key = ::Ed25519::SigningKey.generate
          log.info 'Ed25519 keypair generated'
          {
            private_key:    signing_key.to_bytes,
            public_key:     signing_key.verify_key.to_bytes,
            public_key_hex: signing_key.verify_key.to_bytes.unpack1('H*')
          }
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.ed25519.generate_keypair')
          raise
        end

        def sign(message, private_key_bytes)
          signing_key = ::Ed25519::SigningKey.new(private_key_bytes)
          result = signing_key.sign(message)
          log.debug 'Ed25519 sign complete'
          result
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.ed25519.sign')
          raise
        end

        def verify(message, signature, public_key_bytes)
          verify_key = ::Ed25519::VerifyKey.new(public_key_bytes)
          verify_key.verify(signature, message)
          log.debug 'Ed25519 verify success'
          true
        rescue ::Ed25519::VerifyError => e
          handle_exception(e, level: :debug, operation: 'crypt.ed25519.verify.signature_mismatch')
          log.warn 'Ed25519 signature verification failed'
          false
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.ed25519.verify')
          raise
        end

        def store_keypair(agent_id:, keypair: nil)
          keypair ||= generate_keypair
          if defined?(Legion::Crypt::Vault)
            log.info "Ed25519 storing keypair for agent #{agent_id}"
            Legion::Crypt::Vault.write("#{key_prefix}/#{agent_id}", {
                                         private_key: keypair[:private_key].unpack1('H*'),
                                         public_key:  keypair[:public_key_hex]
                                       })
          else
            log.warn "Ed25519 keypair generated for agent #{agent_id} but Vault is unavailable"
          end
          keypair
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.ed25519.store_keypair', agent_id: agent_id)
          raise
        end

        def load_private_key(agent_id:)
          log.debug "Ed25519 loading private key for agent #{agent_id}"
          data = Legion::Crypt::Vault.read("#{key_prefix}/#{agent_id}")
          if data&.dig(:private_key)
            log.info "Ed25519 private key loaded for agent #{agent_id}"
            [data[:private_key]].pack('H*')
          else
            log.warn "Ed25519 private key missing for agent #{agent_id}"
            nil
          end
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.ed25519.load_private_key', agent_id: agent_id)
          nil
        end

        private

        def key_prefix
          begin
            Legion::Settings[:crypt][:ed25519][:vault_key_prefix]
          rescue StandardError => e
            handle_exception(e, level: :debug, operation: 'crypt.ed25519.key_prefix')
            nil
          end || 'secret/data/legion/keys'
        end
      end
    end
  end
end
