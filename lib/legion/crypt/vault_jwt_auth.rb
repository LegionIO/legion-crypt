# frozen_string_literal: true

module Legion
  module Crypt
    # Vault JWT auth backend integration.
    #
    # Allows Legion workers to authenticate to Vault using JWT tokens
    # via Vault's JWT/OIDC auth method. The worker presents a signed JWT
    # and receives a Vault token with policies scoped to the worker's role.
    #
    # Vault config prerequisites:
    #   vault auth enable jwt
    #   vault write auth/jwt/config jwks_url="..." (or bound_issuer + jwt_validation_pubkeys)
    #   vault write auth/jwt/role/legion-worker bound_audiences="legion" ...
    module VaultJwtAuth
      DEFAULT_AUTH_PATH = 'auth/jwt/login'
      DEFAULT_ROLE      = 'legion-worker'

      class AuthError < StandardError; end

      # Authenticate to Vault using a JWT token.
      # Returns a Vault token string on success.
      #
      # @param jwt [String] Signed JWT token (issued by Legion or Entra ID)
      # @param role [String] Vault JWT auth role name (default: 'legion-worker')
      # @param auth_path [String] Vault auth mount path (default: 'auth/jwt/login')
      # @return [Hash] { token:, lease_duration:, policies:, metadata: }
      def self.login(jwt:, role: DEFAULT_ROLE, auth_path: DEFAULT_AUTH_PATH)
        raise AuthError, 'Vault is not connected' unless vault_connected?

        response = ::Vault.logical.write(
          auth_path,
          role: role,
          jwt:  jwt
        )

        raise AuthError, 'Vault JWT auth returned no auth data' unless response&.auth

        {
          token:          response.auth.client_token,
          lease_duration: response.auth.lease_duration,
          renewable:      response.auth.renewable,
          policies:       response.auth.policies,
          metadata:       response.auth.metadata
        }
      rescue ::Vault::HTTPClientError => e
        Legion::Logging.warn "Vault JWT auth failed (client error): role=#{role}, #{e.message}" if defined?(Legion::Logging)
        raise AuthError, "Vault JWT auth failed: #{e.message}"
      rescue ::Vault::HTTPServerError => e
        Legion::Logging.warn "Vault JWT auth failed (server error): role=#{role}, #{e.message}" if defined?(Legion::Logging)
        raise AuthError, "Vault server error during JWT auth: #{e.message}"
      end

      # Authenticate and set the Vault client token for subsequent operations.
      # This replaces the current Vault token with the JWT-authenticated one.
      #
      # @return [Hash] Same as login
      def self.login!(jwt:, role: DEFAULT_ROLE, auth_path: DEFAULT_AUTH_PATH)
        result = login(jwt: jwt, role: role, auth_path: auth_path)
        ::Vault.token = result[:token]
        Legion::Logging.info "[crypt:vault_jwt] authenticated via JWT auth, policies=#{result[:policies].join(',')}"
        result
      end

      # Issue a Legion JWT and use it to authenticate to Vault in one step.
      # Convenience method for workers that need Vault access.
      #
      # @param worker_id [String] Digital worker ID
      # @param owner_msid [String] Worker's owner MSID
      # @param role [String] Vault JWT auth role name
      # @return [Hash] Same as login
      def self.worker_login(worker_id:, owner_msid:, role: DEFAULT_ROLE)
        jwt = Legion::Crypt::JWT.issue(
          { worker_id: worker_id, sub: owner_msid, scope: 'vault', aud: 'legion' },
          signing_key: Legion::Crypt.cluster_secret,
          ttl:         300,
          issuer:      'legion'
        )

        login(jwt: jwt, role: role)
      end

      def self.vault_connected?
        defined?(::Vault) &&
          defined?(Legion::Settings) &&
          Legion::Settings[:crypt][:vault][:connected] == true
      rescue StandardError
        false
      end

      private_class_method :vault_connected?
    end
  end
end
