# frozen_string_literal: true

require 'securerandom'
require 'legion/logging/helper'
require 'legion/crypt/cluster_secret'

module Legion
  module Crypt
    module Cipher
      include Legion::Crypt::ClusterSecret
      include Legion::Logging::Helper

      def encrypt(message)
        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.encrypt
        cipher.key = cs
        iv = cipher.random_iv
        result = { enciphered_message: Base64.encode64(cipher.update(message) + cipher.final), iv: Base64.encode64(iv) }
        log.debug 'Cipher encrypt completed'
        result
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cipher.encrypt')
        raise
      end

      def decrypt(message, init_vector)
        until cs.is_a?(String) || Legion::Settings[:client][:shutting_down]
          log.debug('sleeping Legion::Crypt.decrypt due to CS not being set')
          sleep(0.5)
        end

        decipher = OpenSSL::Cipher.new('aes-256-cbc')
        decipher.decrypt
        decipher.key = cs
        decipher.iv = Base64.decode64(init_vector)
        message = Base64.decode64(message)
        result = decipher.update(message) + decipher.final
        log.debug 'Cipher decrypt completed'
        result
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cipher.decrypt')
        raise
      end

      def encrypt_from_keypair(message:, pub_key: public_key)
        rsa_public_key = OpenSSL::PKey::RSA.new(pub_key)

        encrypted_message = Base64.encode64(rsa_public_key.public_encrypt(message))
        log.debug 'Cipher keypair encryption completed'
        encrypted_message
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cipher.encrypt_from_keypair')
        raise
      end

      def decrypt_from_keypair(message:, **_opts)
        decrypted_message = private_key.private_decrypt(Base64.decode64(message))
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
    end
  end
end
