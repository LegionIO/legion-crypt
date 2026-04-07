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

    RMQ_ROLE_MAP = {
      agent:  'legionio-infra',
      worker: 'legionio-worker',
      infra:  'legionio-infra'
    }.freeze

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
        lifecycle_mutex.synchronize do
          if @started
            log.info 'Legion::Crypt start ignored because the lifecycle is already running'
            return
          end

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
          @started = true
          log.info 'Legion::Crypt startup completed'
        end
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

      def dynamic_rmq_creds?
        Legion::Settings.dig(:crypt, :vault, :dynamic_rmq_creds) == true
      end

      def fetch_bootstrap_rmq_creds
        return unless vault_connected? && dynamic_rmq_creds?

        Legion::Settings.merge_settings('transport', Legion::Transport::Settings.default) if defined?(Legion::Transport::Settings)

        response = LeaseManager.instance.vault_logical.read('rabbitmq/creds/legionio-bootstrap')
        return unless response&.data

        bootstrap_lease_ttl = Legion::Settings.dig(:crypt, :vault, :bootstrap_lease_ttl).to_i
        bootstrap_lease_ttl = 300 if bootstrap_lease_ttl <= 0

        @bootstrap_lease_id = response.lease_id
        @bootstrap_lease_expires = Time.now + [response.lease_duration, bootstrap_lease_ttl].min

        settings = Legion::Settings.loader.settings
        settings[:transport] ||= {}
        settings[:transport][:connection] ||= {}
        conn = settings[:transport][:connection]
        conn[:user]     = response.data[:username]
        conn[:password] = response.data[:password]

        log.info "Bootstrap RMQ credentials acquired (lease: #{@bootstrap_lease_id[0..7]}...)"
      rescue StandardError => e
        log.warn "Bootstrap RMQ credential fetch failed: #{e.message}"
      end

      def swap_to_identity_creds(mode:)
        return unless vault_connected? && dynamic_rmq_creds?
        return if mode == :lite

        role = RMQ_ROLE_MAP.fetch(mode, "legionio-#{mode}")
        response = LeaseManager.instance.vault_logical.read("rabbitmq/creds/#{role}")
        raise "Failed to fetch identity-scoped RMQ creds for role #{role}" unless response&.data

        LeaseManager.instance.register_dynamic_lease(
          name:          :rabbitmq,
          path:          "rabbitmq/creds/#{role}",
          response:      response,
          settings_refs: [
            { path: %i[transport connection user],     key: :username },
            { path: %i[transport connection password], key: :password }
          ]
        )

        settings = Legion::Settings.loader.settings
        settings[:transport] ||= {}
        settings[:transport][:connection] ||= {}
        conn = settings[:transport][:connection]
        conn[:user]     = response.data[:username]
        conn[:password] = response.data[:password]

        if defined?(Legion::Transport::Connection)
          Legion::Transport::Connection.force_reconnect
          raise 'Transport reconnect failed after credential swap — bootstrap lease NOT revoked' unless Legion::Transport::Connection.session_open?

          log.info "Transport reconnected with identity-scoped creds (role: #{role})"
        end

        revoke_bootstrap_lease
      end

      def revoke_bootstrap_lease
        return unless @bootstrap_lease_id

        LeaseManager.instance.vault_sys.revoke(@bootstrap_lease_id)
        log.info "Bootstrap RMQ lease revoked (#{@bootstrap_lease_id[0..7]}...)"
        @bootstrap_lease_id      = nil
        @bootstrap_lease_expires = nil
      rescue StandardError => e
        log.warn "Bootstrap lease revocation failed: #{e.message} — lease will expire naturally"
        @bootstrap_lease_id      = nil
        @bootstrap_lease_expires = nil
      end

      def vault_connected?
        return true if settings.dig(:vault, :connected) == true
        return true if respond_to?(:connected_clusters) && connected_clusters.any?

        false
      rescue StandardError => e
        handle_exception(e, level: :debug, operation: 'crypt.vault_connected?')
        false
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
        lifecycle_mutex.synchronize do
          unless @started
            log.info 'Legion::Crypt shutdown ignored because the lifecycle is not running'
            return
          end

          log.info 'Legion::Crypt shutdown initiated'
          Legion::Crypt::LeaseManager.instance.shutdown
          stop_token_renewers
          shutdown_renewer
          close_sessions
          stop_svid_rotation
          @started = false
          log.info 'Legion::Crypt shutdown completed'
        end
      end

      private

      def start_lease_manager
        leases = settings.dig(:vault, :leases) || {}
        vault_ok = connected_clusters.any? || settings.dig(:vault, :connected)

        return if leases.empty? && !dynamic_rmq_creds?
        return unless vault_ok

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

        unless leases.empty?
          fetched = lease_manager.fetched_count
          defined = leases.size
          if fetched == defined
            log.info "LeaseManager: #{fetched} lease(s) initialized"
          else
            log.warn "LeaseManager: #{fetched}/#{defined} lease(s) initialized (#{defined - fetched} failed)"
          end
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

      def lifecycle_mutex
        @lifecycle_mutex ||= Mutex.new
      end
    end
  end
end
