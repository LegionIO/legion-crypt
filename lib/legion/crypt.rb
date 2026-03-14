# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'legion/crypt/version'
require 'legion/crypt/settings'
require 'legion/crypt/cipher'
require 'legion/crypt/jwt'
require 'legion/crypt/vault_jwt_auth'

module Legion
  module Crypt
    class << self
      attr_reader :sessions

      include Legion::Crypt::Cipher

      unless Gem::Specification.find_by_name('vault').nil?
        require 'legion/crypt/vault'
        include Legion::Crypt::Vault
      end

      def start
        Legion::Logging.debug 'Legion::Crypt is running start'
        ::File.write('./legionio.key', private_key) if settings[:save_private_key]

        connect_vault unless settings[:vault][:token].nil?
      end

      def settings
        if Legion.const_defined?('Settings')
          Legion::Settings[:crypt]
        else
          Legion::Crypt::Settings.default
        end
      end

      def jwt_settings
        settings[:jwt] || Legion::Crypt::Settings.jwt
      end

      def issue_token(payload = {}, ttl: nil, algorithm: nil)
        jwt = jwt_settings
        algo = algorithm || jwt[:default_algorithm]
        token_ttl = ttl || jwt[:default_ttl]

        signing_key = algo == 'RS256' ? private_key : settings[:cluster_secret]

        Legion::Crypt::JWT.issue(payload, signing_key: signing_key, algorithm: algo, ttl: token_ttl,
                                          issuer: jwt[:issuer])
      end

      def verify_token(token, algorithm: nil)
        jwt = jwt_settings
        algo = algorithm || jwt[:default_algorithm]

        verification_key = algo == 'RS256' ? OpenSSL::PKey::RSA.new(public_key) : settings[:cluster_secret]

        Legion::Crypt::JWT.verify(token, verification_key: verification_key, algorithm: algo,
                                         verify_expiration: jwt[:verify_expiration],
                                         verify_issuer: jwt[:verify_issuer],
                                         issuer: jwt[:issuer])
      end

      def shutdown
        shutdown_renewer
        close_sessions
      end
    end
  end
end
