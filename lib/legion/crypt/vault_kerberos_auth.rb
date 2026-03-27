# frozen_string_literal: true

module Legion
  module Crypt
    module VaultKerberosAuth
      DEFAULT_AUTH_PATH = 'auth/kerberos/login'

      class AuthError < StandardError; end

      def self.login(spnego_token:, auth_path: DEFAULT_AUTH_PATH)
        raise AuthError, 'Vault is not connected' unless vault_connected?

        response = ::Vault.logical.write(auth_path, authorization: "Negotiate #{spnego_token}")
        raise AuthError, 'Vault Kerberos auth returned no auth data' unless response&.auth

        {
          token:          response.auth.client_token,
          lease_duration: response.auth.lease_duration,
          renewable:      response.auth.renewable?,
          policies:       response.auth.policies,
          metadata:       response.auth.metadata
        }
      rescue ::Vault::HTTPClientError => e
        raise AuthError, "Vault Kerberos auth failed: #{e.message}"
      end

      def self.login!(spnego_token:, auth_path: DEFAULT_AUTH_PATH)
        result = login(spnego_token: spnego_token, auth_path: auth_path)
        ::Vault.token = result[:token]
        result
      end

      def self.vault_connected?
        defined?(::Vault) && defined?(Legion::Settings) &&
          Legion::Settings[:crypt][:vault][:connected] == true
      rescue StandardError => e
        Legion::Logging.debug("Legion::Crypt::VaultKerberosAuth#vault_connected? failed: #{e.message}") if defined?(Legion::Logging)
        false
      end

      private_class_method :vault_connected?
    end
  end
end
