# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'legion/crypt/version'
require 'legion/crypt/settings'
require 'legion/crypt/cipher'
require 'legion/crypt/jwt'
require 'legion/crypt/vault_jwt_auth'
require 'legion/crypt/lease_manager'
require 'legion/crypt/vault_cluster'
require 'legion/crypt/ldap_auth'
require 'legion/crypt/token_renewer'
require 'legion/crypt/helper'
require 'legion/crypt/mtls'
require 'legion/crypt/cert_rotation'

module Legion
  module Crypt
    extend Legion::Crypt::VaultCluster
    extend Legion::Crypt::LdapAuth

    class << self
      attr_reader :sessions

      include Legion::Crypt::Cipher

      unless Gem::Specification.find_by_name('vault').nil?
        require 'legion/crypt/vault'
        include Legion::Crypt::Vault
      end

      def vault_settings
        Legion::Settings[:crypt][:vault]
      end

      def kerberos_principal
        KerberosAuth.kerberos_principal
      end

      def start
        Legion::Logging.debug 'Legion::Crypt is running start'
        ::File.write('./legionio.key', private_key) if settings[:save_private_key]
        @token_renewers ||= []

        if vault_settings[:clusters]&.any?
          connect_all_clusters
          start_token_renewers
        else
          connect_vault unless settings[:vault][:token].nil?
        end
        start_lease_manager
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

      def verify_external_token(token, jwks_url:, **)
        Legion::Crypt::JWT.verify_with_jwks(token, jwks_url: jwks_url, **)
      end

      def shutdown
        Legion::Crypt::LeaseManager.instance.shutdown
        stop_token_renewers
        shutdown_renewer
        close_sessions
      end

      private

      def start_lease_manager
        leases = settings.dig(:vault, :leases) || {}
        return if leases.empty?
        return unless settings.dig(:vault, :connected) || connected_clusters.any?

        client = nil

        if settings.dig(:vault, :connected)
          client = vault_client
        elsif connected_clusters.any?
          default_cluster = vault_settings[:default]
          selected_cluster =
            if default_cluster && connected_clusters.include?(default_cluster.to_sym)
              default_cluster.to_sym
            else
              connected_clusters.keys.first
            end

          client = selected_cluster ? vault_client(selected_cluster) : nil
        end
        lease_manager = Legion::Crypt::LeaseManager.instance
        lease_manager.start(leases, vault_client: client)
        lease_manager.start_renewal_thread
        Legion::Logging.info "LeaseManager: #{leases.size} lease(s) initialized"
      rescue StandardError => e
        Legion::Logging.warn "LeaseManager startup failed: #{e.message}"
      end

      def start_token_renewers
        clusters.each do |name, config|
          next unless config[:auth_method]&.to_s == 'kerberos' && config[:connected]

          renewer = Legion::Crypt::TokenRenewer.new(
            cluster_name: name,
            config:       config,
            vault_client: vault_client(name)
          )
          renewer.start
          @token_renewers << renewer
        end
      end

      def stop_token_renewers
        return unless @token_renewers

        @token_renewers.each(&:stop)
        @token_renewers.clear
      end
    end
  end
end
