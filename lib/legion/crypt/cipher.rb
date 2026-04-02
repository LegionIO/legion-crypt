# frozen_string_literal: true

require 'securerandom'
require 'legion/logging/helper'
require 'legion/crypt/cluster_secret'

module Legion
  module Crypt
    module Cipher
      AUTHENTICATED_CIPHER = 'aes-256-gcm'
      LEGACY_CIPHER = 'aes-256-cbc'
      AUTHENTICATED_PREFIX = 'gcm'
      RSA_OAEP_PREFIX = 'oaep'
      RSA_OAEP_PADDING = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      RSA_LEGACY_PADDING = OpenSSL::PKey::RSA::PKCS1_PADDING

      include Legion::Crypt::ClusterSecret
      include Legion::Logging::Helper

      def encrypt(message)
        cipher = OpenSSL::Cipher.new(AUTHENTICATED_CIPHER)
        cipher.encrypt
        cipher.key = cs
        iv = cipher.random_iv
        ciphertext = cipher.update(message) + cipher.final
        encoded_ciphertext = Base64.strict_encode64(ciphertext)
        encoded_auth_tag = Base64.strict_encode64(cipher.auth_tag)
        result = {
          enciphered_message: "#{AUTHENTICATED_PREFIX}:#{encoded_ciphertext}:#{encoded_auth_tag}",
          iv:                 Base64.strict_encode64(iv)
        }
        log.debug 'Cipher encrypt completed'
        result
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cipher.encrypt')
        raise
      end

      def decrypt(message, init_vector)
        secret = wait_for_cluster_secret
        result = if authenticated_ciphertext?(message)
                   decrypt_authenticated(message, init_vector, secret)
                 else
                   decrypt_legacy(message, init_vector, secret)
                 end
        log.debug 'Cipher decrypt completed'
        result
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cipher.decrypt')
        raise
      end

      def encrypt_from_keypair(message:, pub_key: public_key)
        rsa_public_key = OpenSSL::PKey::RSA.new(pub_key)

        encrypted_message = rsa_public_key.public_encrypt(message, RSA_OAEP_PADDING)
        encoded_message = "#{RSA_OAEP_PREFIX}:#{Base64.strict_encode64(encrypted_message)}"
        log.debug 'Cipher keypair encryption completed'
        encoded_message
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cipher.encrypt_from_keypair')
        raise
      end

      def decrypt_from_keypair(message:, **_opts)
        decrypted_message = if rsa_oaep_ciphertext?(message)
                              decrypt_oaep_from_keypair(message)
                            else
                              decrypt_legacy_from_keypair(message)
                            end
        log.debug 'Cipher keypair decryption completed'
        decrypted_message
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cipher.decrypt_from_keypair')
        raise
      end

      def public_key
        @public_key ||= private_key.public_key.to_s
      end

      def private_key
        @private_key ||= if Legion::Settings[:crypt][:read_private_key] && File.exist?('./legionio.key')
                           log.info 'Cipher loading RSA private key from disk'
                           OpenSSL::PKey::RSA.new File.read './legionio.key'
                         else
                           log.info 'Cipher generating RSA private key'
                           OpenSSL::PKey::RSA.new 2048
                         end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cipher.private_key')
        raise
      end

      private

      def wait_for_cluster_secret
        loop do
          secret = cs
          return secret if secret.is_a?(String)
          break if Legion::Settings[:client][:shutting_down]

          log.debug('sleeping Legion::Crypt.decrypt due to CS not being set')
          sleep(0.5)
        end

        cs
      end

      def authenticated_ciphertext?(message)
        message.start_with?("#{AUTHENTICATED_PREFIX}:")
      end

      def decrypt_authenticated(message, init_vector, secret)
        _, encoded_ciphertext, encoded_auth_tag = message.split(':', 3)

        decipher = OpenSSL::Cipher.new(AUTHENTICATED_CIPHER)
        decipher.decrypt
        decipher.key = secret
        decipher.iv = Base64.strict_decode64(init_vector)
        decipher.auth_tag = Base64.strict_decode64(encoded_auth_tag)
        decipher.update(Base64.strict_decode64(encoded_ciphertext)) + decipher.final
      end

      def decrypt_legacy(message, init_vector, secret)
        decipher = OpenSSL::Cipher.new(LEGACY_CIPHER)
        decipher.decrypt
        decipher.key = secret
        decipher.iv = Base64.decode64(init_vector)
        decipher.update(Base64.decode64(message)) + decipher.final
      end

      def rsa_oaep_ciphertext?(message)
        message.start_with?("#{RSA_OAEP_PREFIX}:")
      end

      def decrypt_oaep_from_keypair(message)
        _, encoded_message = message.split(':', 2)
        private_key.private_decrypt(Base64.strict_decode64(encoded_message), RSA_OAEP_PADDING)
      end

      def decrypt_legacy_from_keypair(message)
        private_key.private_decrypt(Base64.decode64(message), RSA_LEGACY_PADDING)
      end
    end
  end
end
