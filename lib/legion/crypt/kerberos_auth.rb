# frozen_string_literal: true

module Legion
  module Crypt
    module KerberosAuth
      class AuthError < StandardError; end
      class GemMissingError < StandardError; end

      DEFAULT_AUTH_PATH = 'auth/kerberos/login'

      def self.login(vault_client:, service_principal:, auth_path: DEFAULT_AUTH_PATH)
        raise GemMissingError, 'lex-kerberos gem is required for Kerberos auth' unless spnego_available?

        token = obtain_token(service_principal)
        exchange_token(vault_client, token, auth_path)
      end

      def self.spnego_available?
        return @spnego_available unless @spnego_available.nil?

        @spnego_available = begin
          require 'legion/extensions/kerberos/helpers/spnego'
          true
        rescue LoadError
          # check if constant was already defined (e.g. stubbed in tests or loaded via another path)
          defined?(Legion::Extensions::Kerberos::Helpers::Spnego) ? true : false
        end
      end

      def self.reset!
        @spnego_available = nil
      end

      class << self
        private

        def obtain_token(service_principal)
          helper = Object.new.extend(Legion::Extensions::Kerberos::Helpers::Spnego)
          result = helper.obtain_spnego_token(service_principal: service_principal)
          raise AuthError, "SPNEGO token acquisition failed: #{result[:error]}" unless result[:success]

          result[:token]
        end

        def exchange_token(vault_client, spnego_token, auth_path)
          response = vault_client.logical.write(auth_path, authorization: "Negotiate #{spnego_token}")
          raise AuthError, 'Vault Kerberos auth returned no auth data' unless response&.auth

          {
            token:          response.auth.client_token,
            lease_duration: response.auth.lease_duration,
            renewable:      response.auth.renewable,
            policies:       response.auth.policies,
            metadata:       response.auth.metadata
          }
        rescue ::Vault::HTTPClientError => e
          raise AuthError, "Vault Kerberos auth failed: #{e.message}"
        end
      end
    end
  end
end
