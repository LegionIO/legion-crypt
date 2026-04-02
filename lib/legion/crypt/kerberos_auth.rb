# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    module KerberosAuth
      class AuthError < StandardError; end
      class GemMissingError < StandardError; end

      DEFAULT_AUTH_PATH = 'auth/kerberos/login'

      @kerberos_principal = nil
      extend Legion::Logging::Helper

      class << self
        attr_reader :kerberos_principal
      end

      def self.login(vault_client:, service_principal:, auth_path: DEFAULT_AUTH_PATH)
        raise GemMissingError, 'lex-kerberos gem is required for Kerberos auth' unless spnego_available?

        log.info "KerberosAuth login requested auth_path=#{auth_path}"
        log.debug("KerberosAuth: login: SPN=#{service_principal}, auth_path=#{auth_path}")
        addr = vault_client.respond_to?(:address) ? vault_client.address : 'n/a'
        ns   = vault_client.respond_to?(:namespace) ? vault_client.namespace.inspect : 'n/a'
        log.debug("KerberosAuth: login: vault_client.address=#{addr}, namespace=#{ns}")

        @kerberos_principal = nil
        token = obtain_token(service_principal)
        log.debug("KerberosAuth: login: SPNEGO token obtained (#{token.length} chars)")

        result = exchange_token(vault_client, token, auth_path)
        @kerberos_principal = result[:metadata]&.dig('username') || result[:metadata]&.dig(:username)
        log.debug("KerberosAuth: login: authenticated as #{@kerberos_principal.inspect}, policies=#{result[:policies].inspect}")
        log.debug("KerberosAuth: login: renewable=#{result[:renewable]}, ttl=#{result[:lease_duration]}s")
        log.info "KerberosAuth login success principal=#{@kerberos_principal || 'unknown'} auth_path=#{auth_path}"
        result
      end

      def self.spnego_available?
        return @spnego_available unless @spnego_available.nil?

        @spnego_available = begin
          require 'legion/extensions/kerberos/helpers/spnego'
          true
        rescue LoadError => e
          handle_exception(e, level: :debug, operation: 'crypt.kerberos_auth.spnego_available')
          # check if constant was already defined (e.g. stubbed in tests or loaded via another path)
          defined?(Legion::Extensions::Kerberos::Helpers::Spnego) ? true : false
        end
      end

      def self.reset!
        @spnego_available = nil
        @kerberos_principal = nil
      end

      class << self
        private

        def obtain_token(service_principal)
          helper = Object.new.extend(Legion::Extensions::Kerberos::Helpers::Spnego)
          result = helper.obtain_spnego_token(service_principal: service_principal)
          raise AuthError, "SPNEGO token acquisition failed: #{result[:error]}" unless result[:success]

          log.info 'KerberosAuth obtained SPNEGO token'
          result[:token]
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.kerberos_auth.obtain_token', auth_method: 'kerberos')
          raise
        end

        def exchange_token(vault_client, spnego_token, auth_path)
          # Kerberos auth is mounted inside the target namespace. Keep the
          # client namespace so the token is scoped to it.

          # The Vault Kerberos plugin reads the SPNEGO token from the HTTP
          # Authorization header, not the JSON body.
          namespace = vault_client.respond_to?(:namespace) ? vault_client.namespace.inspect : 'n/a'
          log.debug("KerberosAuth: exchange_token: PUT /v1/#{auth_path} (namespace=#{namespace})")
          json = vault_client.put(
            "/v1/#{auth_path}",
            '{}',
            'Authorization' => "Negotiate #{spnego_token}"
          )
          response = ::Vault::Secret.decode(json)
          raise AuthError, 'Vault Kerberos auth returned no auth data' unless response&.auth

          auth = response.auth
          {
            token:          auth.client_token,
            lease_duration: auth.lease_duration,
            renewable:      auth.renewable?,
            policies:       auth.policies,
            metadata:       auth.metadata
          }
        rescue ::Vault::HTTPClientError => e
          handle_exception(e, level: :warn, operation: 'crypt.kerberos_auth.exchange_token', auth_path: auth_path)
          log.debug("KerberosAuth: exchange_token: HTTP error: #{e.message}")
          raise AuthError, "Vault Kerberos auth failed: #{e.message}"
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.kerberos_auth.exchange_token', auth_path: auth_path)
          raise
        end
      end
    end
  end
end
