# frozen_string_literal: true

require 'securerandom'
require 'legion/crypt/cluster_secret'

module Legion
  module Crypt
    module Cipher
      include Legion::Crypt::ClusterSecret

      def encrypt(message)
        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.encrypt
        cipher.key = cs
        iv = cipher.random_iv
        { enciphered_message: Base64.encode64(cipher.update(message) + cipher.final), iv: Base64.encode64(iv) }
      end

      def decrypt(message, iv)
        until cs.is_a?(String) || Legion::Settings[:client][:shutting_down]
          Legion::Logging.debug('sleeping Legion::Crypt.decrypt due to CS not being set')
          sleep(0.5)
        end

        decipher = OpenSSL::Cipher.new('aes-256-cbc')
        decipher.decrypt
        decipher.key = cs
        decipher.iv = Base64.decode64(iv)
        message = Base64.decode64(message)
        decipher.update(message) + decipher.final
      end

      def encrypt_from_keypair(message:, pub_key: public_key)
        rsa_public_key = OpenSSL::PKey::RSA.new(pub_key)

        Base64.encode64(rsa_public_key.public_encrypt(message))
      end

      def decrypt_from_keypair(message:, **_opts)
        private_key.private_decrypt(Base64.decode64(message))
      end

      def public_key
        @public_key ||= private_key.public_key.to_s
      end

      def private_key
        @private_key ||= if Legion::Settings[:crypt][:read_private_key] && File.exist?('./legionio.key')
                           OpenSSL::PKey::RSA.new File.read './legionio.key'
                         else
                           OpenSSL::PKey::RSA.new 2048
                         end
      end
    end
  end
end
