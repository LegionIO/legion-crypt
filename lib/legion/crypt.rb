# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'legion/logging/helper'
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
require 'legion/crypt/spiffe'
require 'legion/crypt/spiffe/workload_api_client'
require 'legion/crypt/spiffe/svid_rotation'
require 'legion/crypt/spiffe/identity_helpers'

module Legion
  module Crypt
    extend Legion::Crypt::VaultCluster
    extend Legion::Crypt::LdapAuth

    class << self
      attr_reader :sessions

      include Legion::Logging::Helper
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

      def spiffe_svid
        @svid_rotation&.current_svid
      end

      def fetch_svid
        @workload_client ||= Spiffe::WorkloadApiClient.new
        @workload_client.fetch_x509_svid
      end

      def fetch_jwt_svid(audience:)
        @workload_client ||= Spiffe::WorkloadApiClient.new
        @workload_client.fetch_jwt_svid(audience: audience)
      end

      def start
        log.info 'Legion::Crypt startup initiated'
        log.debug 'Legion::Crypt start requested'
        ::File.write('./legionio.key', private_key) if settings[:save_private_key]
        @token_renewers ||= []

        if vault_settings[:clusters]&.any?
          log.info "Legion::Crypt connecting #{vault_settings[:clusters].size} Vault cluster(s)"
          connect_all_clusters
          start_token_renewers
        else
          log.info 'Legion::Crypt connecting primary Vault client' unless settings[:vault][:token].nil?
          connect_vault unless settings[:vault][:token].nil?
        end
        start_lease_manager
        start_svid_rotation
        log.info 'Legion::Crypt startup completed'
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
        log.info 'Legion::Crypt shutdown initiated'
        Legion::Crypt::LeaseManager.instance.shutdown
        stop_token_renewers
        shutdown_renewer
        close_sessions
        stop_svid_rotation
        log.info 'Legion::Crypt shutdown completed'
      end

      private

      def start_lease_manager
        leases = settings.dig(:vault, :leases) || {}
        return if leases.empty?
        return unless connected_clusters.any? || settings.dig(:vault, :connected)

        client = nil

        if connected_clusters.any?
          selected_cluster = selected_connected_cluster_name
          client = selected_cluster ? vault_client(selected_cluster) : nil
        elsif settings.dig(:vault, :connected)
          client = vault_client
        end
        lease_manager = Legion::Crypt::LeaseManager.instance
        lease_manager.start(leases, vault_client: client)
        lease_manager.start_renewal_thread
        fetched = lease_manager.fetched_count
        defined = leases.size
        if fetched == defined
          log.info "LeaseManager: #{fetched} lease(s) initialized"
        else
          log.warn "LeaseManager: #{fetched}/#{defined} lease(s) initialized (#{defined - fetched} failed)"
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.start_lease_manager')
      end

      def start_token_renewers
        started = 0
        clusters.each do |name, config|
          next unless config[:auth_method]&.to_s == 'kerberos' && config[:connected]

          renewer = Legion::Crypt::TokenRenewer.new(
            cluster_name: name,
            config:       config,
            vault_client: vault_client(name)
          )
          renewer.start
          @token_renewers << renewer
          started += 1
        end
        log.info "Legion::Crypt started #{started} token renewer(s)" if started.positive?
      end

      def stop_token_renewers
        return unless @token_renewers

        @token_renewers.each(&:stop)
        log.info "Legion::Crypt stopped #{@token_renewers.size} token renewer(s)" if @token_renewers.any?
        @token_renewers.clear
      end

      def start_svid_rotation
        return unless Spiffe.enabled?

        log.info 'Legion::Crypt starting SPIFFE SVID rotation'
        @svid_rotation = Spiffe::SvidRotation.new
        @svid_rotation.start
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.start_svid_rotation')
      end

      def stop_svid_rotation
        return unless @svid_rotation

        log.info 'Legion::Crypt stopping SPIFFE SVID rotation'
        @svid_rotation.stop
        @svid_rotation = nil
      end
    end
  end
end
