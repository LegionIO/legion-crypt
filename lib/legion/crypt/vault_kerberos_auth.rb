# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/vault_client'

module Legion
  module Crypt
    module VaultKerberosAuth
      DEFAULT_AUTH_PATH = 'auth/kerberos/login'

      class AuthError < StandardError; end

      extend Legion::Logging::Helper

      def self.login(spnego_token:, auth_path: DEFAULT_AUTH_PATH)
        raise AuthError, 'Vault is not connected' unless Legion::Crypt.vault_connected?

        log.info "[crypt:vault_kerberos] login requested auth_path=#{auth_path}"
        data = Legion::Crypt.vault_client.put(
          path: auth_path, body: '{}', headers: { 'Authorization' => "Negotiate #{spnego_token}" }
        )
        response = Legion::Crypt::VaultClient::Secret.decode(data: data)
        raise AuthError, 'Vault Kerberos auth returned no auth data' unless response&.auth

        {
          token:          response.auth.client_token,
          lease_duration: response.auth.lease_duration,
          renewable:      response.auth.renewable?,
          policies:       response.auth.policies,
          metadata:       response.auth.metadata
        }
      rescue Legion::Crypt::Vault::HTTPClientError => e
        handle_exception(e, level: :warn, operation: 'crypt.vault_kerberos_auth.login', auth_path: auth_path)
        raise AuthError, "Vault Kerberos auth failed: #{e.message}"
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault_kerberos_auth.login', auth_path: auth_path)
        raise
      end

      def self.login!(spnego_token:, auth_path: DEFAULT_AUTH_PATH)
        generation = Legion::Crypt.vault_auth_generation
        client = Legion::Crypt.vault_client
        config = Legion::Crypt.cluster || Legion::Settings[:crypt][:vault]
        result = login(spnego_token: spnego_token, auth_path: auth_path)
        Legion::Crypt.install_vault_grant(client: client, config: config, grant: result, auth_method: 'kerberos', generation: generation)
        log.info "[crypt:vault_kerberos] authenticated via Kerberos auth, policies=#{result[:policies].join(',')}"
        result
      end
    end
  end
end
