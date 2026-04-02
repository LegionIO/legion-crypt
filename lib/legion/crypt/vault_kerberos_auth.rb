# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    module VaultKerberosAuth
      DEFAULT_AUTH_PATH = 'auth/kerberos/login'

      class AuthError < StandardError; end

      extend Legion::Logging::Helper

      def self.login(spnego_token:, auth_path: DEFAULT_AUTH_PATH)
        raise AuthError, 'Vault is not connected' unless vault_connected?

        log.info "[crypt:vault_kerberos] login requested auth_path=#{auth_path}"
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
        handle_exception(e, level: :warn, operation: 'crypt.vault_kerberos_auth.login', auth_path: auth_path)
        raise AuthError, "Vault Kerberos auth failed: #{e.message}"
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault_kerberos_auth.login', auth_path: auth_path)
        raise
      end

      def self.login!(spnego_token:, auth_path: DEFAULT_AUTH_PATH)
        result = login(spnego_token: spnego_token, auth_path: auth_path)
        ::Vault.token = result[:token]
        log.info "[crypt:vault_kerberos] authenticated via Kerberos auth, policies=#{result[:policies].join(',')}"
        result
      end

      def self.vault_connected?
        defined?(::Vault) && defined?(Legion::Settings) &&
          Legion::Settings[:crypt][:vault][:connected] == true
      rescue StandardError => e
        handle_exception(e, level: :debug, operation: 'crypt.vault_kerberos_auth.vault_connected')
        false
      end

      private_class_method :vault_connected?
    end
  end
end
