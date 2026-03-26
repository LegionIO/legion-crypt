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
          # Kerberos auth is mounted at the root namespace. Temporarily
          # clear the client namespace so the request reaches the correct
          # mount path, then restore it for subsequent operations.
          saved_ns = vault_client.namespace
          vault_client.namespace = nil

          # The Vault Kerberos plugin reads the SPNEGO token from the HTTP
          # Authorization header, not the JSON body.
          json = vault_client.put(
            "/v1/#{auth_path}",
            '{}',
            'Authorization' => "Negotiate #{spnego_token}"
          )
          response = ::Vault::Secret.decode(json)
          raise AuthError, 'Vault Kerberos auth returned no auth data' unless response&.auth

          vault_client.namespace = saved_ns

          auth = response.auth
          {
            token:          auth.client_token,
            lease_duration: auth.lease_duration,
            renewable:      auth.renewable?,
            policies:       auth.policies,
            metadata:       auth.metadata
          }
        rescue ::Vault::HTTPClientError => e
          vault_client.namespace = saved_ns if saved_ns
          raise AuthError, "Vault Kerberos auth failed: #{e.message}"
        end
      end
    end
  end
end
