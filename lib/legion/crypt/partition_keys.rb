# frozen_string_literal: true

require 'openssl'

module Legion
  module Crypt
    module PartitionKeys
      class << self
        def derive_key(master_key:, tenant_id:, context: nil)
          context ||= begin
            Legion::Settings[:crypt][:partition_keys][:derivation_context]
          rescue StandardError
            nil
          end || 'legion-partition'
          salt = OpenSSL::Digest::SHA256.digest(tenant_id.to_s)
          OpenSSL::KDF.hkdf(master_key, salt: salt, info: context, length: 32, hash: 'SHA256')
        end

        def encrypt_for_tenant(plaintext:, tenant_id:, master_key:)
          key = derive_key(master_key: master_key, tenant_id: tenant_id)
          cipher = OpenSSL::Cipher.new('aes-256-gcm')
          cipher.encrypt
          cipher.key = key
          iv = cipher.random_iv
          ciphertext = cipher.update(plaintext) + cipher.final
          auth_tag = cipher.auth_tag

          { ciphertext: ciphertext, iv: iv, auth_tag: auth_tag }
        end

        def decrypt_for_tenant(ciphertext:, init_vector:, auth_tag:, tenant_id:, master_key:)
          key = derive_key(master_key: master_key, tenant_id: tenant_id)
          decipher = OpenSSL::Cipher.new('aes-256-gcm')
          decipher.decrypt
          decipher.key = key
          decipher.iv = init_vector
          decipher.auth_tag = auth_tag
          decipher.update(ciphertext) + decipher.final
        end
      end
    end
  end
end
