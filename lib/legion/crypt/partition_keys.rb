# frozen_string_literal: true

require 'openssl'
require 'legion/logging/helper'

module Legion
  module Crypt
    module PartitionKeys
      extend Legion::Logging::Helper

      class << self
        def derive_key(master_key:, tenant_id:, context: nil)
          context ||= begin
            Legion::Settings[:crypt][:partition_keys][:derivation_context]
          rescue StandardError => e
            handle_exception(e, level: :debug, operation: 'crypt.partition_keys.derivation_context', tenant_id: tenant_id)
            nil
          end || 'legion-partition'
          log.debug "PartitionKeys deriving key for tenant #{tenant_id}"
          salt = OpenSSL::Digest::SHA256.digest(tenant_id.to_s)
          OpenSSL::KDF.hkdf(master_key, salt: salt, info: context, length: 32, hash: 'SHA256')
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.partition_keys.derive_key', tenant_id: tenant_id)
          raise
        end

        def encrypt_for_tenant(plaintext:, tenant_id:, master_key:)
          key = derive_key(master_key: master_key, tenant_id: tenant_id)
          cipher = OpenSSL::Cipher.new('aes-256-gcm')
          cipher.encrypt
          cipher.key = key
          iv = cipher.random_iv
          ciphertext = cipher.update(plaintext) + cipher.final
          auth_tag = cipher.auth_tag

          log.debug "PartitionKeys encrypted payload for tenant #{tenant_id}"
          { ciphertext: ciphertext, iv: iv, auth_tag: auth_tag }
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.partition_keys.encrypt_for_tenant', tenant_id: tenant_id)
          raise
        end

        def decrypt_for_tenant(ciphertext:, init_vector:, auth_tag:, tenant_id:, master_key:)
          key = derive_key(master_key: master_key, tenant_id: tenant_id)
          decipher = OpenSSL::Cipher.new('aes-256-gcm')
          decipher.decrypt
          decipher.key = key
          decipher.iv = init_vector
          decipher.auth_tag = auth_tag
          plaintext = decipher.update(ciphertext) + decipher.final
          log.debug "PartitionKeys decrypted payload for tenant #{tenant_id}"
          plaintext
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.partition_keys.decrypt_for_tenant', tenant_id: tenant_id)
          raise
        end
      end
    end
  end
end
