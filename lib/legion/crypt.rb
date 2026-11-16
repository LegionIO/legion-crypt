# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'monitor'
require 'legion/logging/helper'
require 'legion/settings'

require 'legion/crypt/version'
require 'legion/crypt/settings'
require 'legion/crypt/cipher'
require 'legion/crypt/jwt'
require 'legion/crypt/vault/operation'
require 'legion/crypt/vault/cluster'
require 'legion/crypt/vault'
require 'legion/crypt/lease_manager'
require 'legion/crypt/helper'
require 'legion/crypt/mtls'
require 'legion/crypt/cert_rotation'
require 'legion/crypt/spiffe'

module Legion
  module Crypt
    extend Legion::Crypt::Vault::Cluster

    RMQ_ROLE_MAP = {
      agent:  'legionio-infra',
      worker: 'legionio-worker',
      infra:  'legionio-infra'
    }.freeze

    POSTGRES_ROLE_MAP = {
      infra: 'infra'
    }.freeze

    class << self
      attr_reader :stopping

      include Legion::Logging::Helper
      include Legion::Crypt::Cipher

      include Legion::Crypt::Vault

      def kerberos_principal(**)
        default_session&.principal
      end

      def ldap_login(cluster_name:, username:, password:, **)
        session = session_for(cluster_name)
        raise KeyError, "Vault cluster not configured: #{cluster_name.inspect}" if session.nil?

        session.login(username: username, password: password)
      end

      def ldap_login_all(username:, password:, **)
        results = {}
        effective_cluster_configs.each do |name, config|
          next unless config[:auth_method]&.to_s == 'ldap'

          results[name] = ldap_login(cluster_name: name, username: username, password: password)
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.ldap_login_all', cluster_name: name)
          message = password.to_s.empty? ? e.message : e.message.gsub(password.to_s, '[REDACTED]')
          results[name] = { error: message }
        end
        results
      end

      def spiffe_svid
        @svid_rotation&.current_svid
      end

      def fetch_svid(**)
        @workload_client ||= Legion::Crypt::Spiffe::WorkloadApiClient.new
        @workload_client.fetch_x509_svid
      end

      def fetch_jwt_svid(audience:, **)
        @workload_client ||= Legion::Crypt::Spiffe::WorkloadApiClient.new
        @workload_client.fetch_jwt_svid(audience: audience)
      end

      def start(mode: nil, **)
        lifecycle_monitor.synchronize do
          if @started || @stopping
            log.info 'Legion::Crypt start ignored because the lifecycle is running or stopping'
            return
          end

          log.info 'Legion::Crypt startup initiated'
          log.debug 'Legion::Crypt start requested'
          if Legion::Settings[:crypt][:save_private_key]
            key = private_key
            ::File.open('./legionio.key', ::File::WRONLY | ::File::CREAT, 0o600) do |file|
              file.chmod(0o600)
              file.truncate(0)
              file.write(key.to_pem)
            end
          end
          start_session_tracking

          if Legion::Settings[:crypt][:vault][:enabled]
            start_vault_sessions(mode: mode)
          else
            log.info 'Legion::Crypt Vault is disabled; skipping Vault authentication and maintenance'
          end
          start_svid_rotation
          @started = true
          log.info 'Legion::Crypt startup completed'
        end
      end

      def dynamic_rmq_creds?
        Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] == true
      end

      def fetch_bootstrap_rmq_creds(**)
        return unless vault_connected? && dynamic_rmq_creds?

        Legion::Settings.merge_settings('transport', Legion::Transport::Settings.default) if defined?(Legion::Transport::Settings)

        response = Legion::Crypt::LeaseManager.instance.vault_logical.read(path: 'rabbitmq/creds/legionio-bootstrap')
        return unless response&.data

        bootstrap_lease_ttl = Legion::Settings[:crypt][:vault][:bootstrap_lease_ttl].to_i
        bootstrap_lease_ttl = 300 if bootstrap_lease_ttl <= 0

        @bootstrap_lease_id = response.lease_id
        @bootstrap_lease_expires = Time.now + [response.lease_duration, bootstrap_lease_ttl].min

        settings = Legion::Settings.loader.settings
        settings[:transport] ||= {}
        settings[:transport][:connection] ||= {}
        conn = settings[:transport][:connection]
        username = response.data[:username] || response.data['username']
        password = response.data[:password] || response.data['password']

        unless username && password
          log.warn 'Bootstrap RMQ credential fetch returned nil username or password — skipping settings update'
          return
        end

        conn[:user]     = username
        conn[:password] = password

        log.info "Bootstrap RMQ credentials acquired (lease: #{@bootstrap_lease_id[0..7]}...)"
      rescue IOError, SystemCallError, Timeout::Error, Faraday::Error, Legion::Crypt::Vault::HTTPError => e
        handle_exception(e, level: :warn, operation: 'crypt.fetch_bootstrap_rmq_creds')
      end

      def swap_to_identity_creds(mode:, **)
        return unless vault_connected? && dynamic_rmq_creds?
        return if mode == :lite

        manager = Legion::Crypt::LeaseManager.instance

        role = RMQ_ROLE_MAP.fetch(mode, "legionio-#{mode}")
        response = Legion::Crypt::Vault::Operation.with_timeout { manager.vault_logical.read(path: "rabbitmq/creds/#{role}") }
        raise "Failed to fetch identity-scoped RMQ creds for role #{role}" unless response

        settings = Legion::Settings.loader.settings
        settings[:transport] ||= {}
        settings[:transport][:connection] ||= {}
        conn = settings[:transport][:connection]
        conn[:user] = nil unless conn.key?(:user)
        conn[:password] = nil unless conn.key?(:password)

        installed = manager.register_dynamic_lease(
          name:          :rabbitmq,
          path:          "rabbitmq/creds/#{role}",
          response:      response,
          settings_refs: [
            { path: %i[transport connection user],     key: :username },
            { path: %i[transport connection password], key: :password }
          ]
        )
        raise 'Identity credential handoff failed — bootstrap lease NOT revoked' unless installed

        Legion::Crypt::Vault::Operation.with_timeout { revoke_bootstrap_lease }
      end

      def revoke_bootstrap_lease(**)
        return unless @bootstrap_lease_id

        Legion::Crypt::LeaseManager.instance.vault_sys.revoke(lease_id: @bootstrap_lease_id)
        log.info "Bootstrap RMQ lease revoked (#{@bootstrap_lease_id[0..7]}...)"
        @bootstrap_lease_id      = nil
        @bootstrap_lease_expires = nil
      rescue IOError, SystemCallError, Timeout::Error, Faraday::Error, Legion::Crypt::Vault::HTTPError => e
        handle_exception(e, level: :warn, operation: 'crypt.revoke_bootstrap_lease')
        @bootstrap_lease_id      = nil
        @bootstrap_lease_expires = nil
      end

      def vault_connected?(**)
        return connected_clusters.any? if Legion::Settings[:crypt][:vault][:clusters].any?

        Legion::Settings[:crypt][:vault][:connected] == true
      end

      def issue_token(payload = {}, ttl: nil, algorithm: nil)
        jwt = Legion::Settings[:crypt][:jwt]
        algo = algorithm || jwt[:default_algorithm]
        token_ttl = ttl || jwt[:default_ttl]
        signing_key = algo == 'RS256' ? private_key : Legion::Settings[:crypt][:cluster_secret]

        Legion::Crypt::JWT.issue(payload, signing_key: signing_key, algorithm: algo, ttl: token_ttl, issuer: jwt[:issuer])
      end

      def verify_token(token, algorithm: nil)
        jwt = Legion::Settings[:crypt][:jwt]
        algo = algorithm || jwt[:default_algorithm]

        verification_key = algo == 'RS256' ? OpenSSL::PKey::RSA.new(public_key) : Legion::Settings[:crypt][:cluster_secret]

        Legion::Crypt::JWT.verify(token, verification_key: verification_key, algorithm: algo,
                                  verify_expiration: jwt[:verify_expiration],
                                  verify_issuer: jwt[:verify_issuer],
                                  issuer: jwt[:issuer])
      end

      def verify_external_token(token, jwks_url:, **)
        Legion::Crypt::JWT.verify_with_jwks(token, jwks_url: jwks_url, **)
      end

      # Stops maintenance, then revokes dependent leases and sessions before the tokens they depend on.
      def shutdown
        shutdown_started = lifecycle_monitor.synchronize do
          return if @stopping
          return unless @started || @vault_clients || @retired_vault_clients&.size&.positive?

          @stopping = true
          @started = false
          true
        end
        deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + Legion::Crypt::Vault::Operation::SHUTDOWN_TIMEOUT

        # Request stop on the sessions first so their maintenance + lease renewal threads are bounded.
        lifecycle_monitor.synchronize { (@vault_sessions || {}).values }.each do |session|
          session.request_stop
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.shutdown.request_stop')
        end

        # Clients whose token Vault rejected are not used for further cleanup.
        denied_clients = {}.compare_by_identity
        components = [
          [self, :stop_svid_rotation, { deadline: deadline }, false],
          [self, :shutdown_renewer, {}, false],
          [self, :stop_vault_sessions, { deadline: deadline, denied_clients: denied_clients }, true],
          [self, :close_sessions, { deadline: deadline, denied_clients: denied_clients }, true],
          [self, :clear_vault_clients, { deadline: deadline }, false]
        ]
        run_shutdown_components(components)
      ensure
        if shutdown_started
          lifecycle_monitor.synchronize do
            @started = false
            @stopping = false
          end
        end
      end

      private

      # Creates one Vault::Session per configured cluster; the default cluster's session also drives
      # the process-wide leases. Multi-cluster by construction; a single cluster is the one-cluster case.
      def start_vault_sessions(mode:)
        default = default_cluster_name
        lease_defs = postgresql_leases_for_mode(leases: Legion::Settings[:crypt][:vault][:leases], mode: mode)
        effective_cluster_configs.each_key do |name|
          client = vault_client(name)
          next if client.nil?

          leases = name == default ? Legion::Crypt::LeaseManager.instance : nil
          session = Legion::Crypt::Vault::Session.new(cluster_name: name, client: client, leases: leases, lease_defs: lease_defs)
          (@vault_sessions ||= {})[name] = session
          session.start
        rescue NameError
          raise # programming error — never swallowed as a Vault outage
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.start_vault_sessions', cluster_name: name)
        end
      end

      # Stops every session (each stops its token thread, shuts down its leases, and revokes its token).
      def stop_vault_sessions(deadline:, denied_clients: {}, **)
        sessions = lifecycle_monitor.synchronize { (@vault_sessions || {}).values.tap { @vault_sessions = {} } }
        sessions.map do |session|
          session.stop(deadline: deadline)
          true
        rescue StandardError => e
          denied_clients[session.client] = true if e.is_a?(Legion::Crypt::Vault::HTTPClientError) && e.code == 403
          handle_exception(e, level: :error, operation: 'crypt.stop_vault_sessions', cluster_name: session.cluster_name, outcome: 'incomplete')
          false
        end.all?
      end

      # Runs each shutdown component in order, collecting the cleanup operations that did not complete.
      def run_shutdown_components(components)
        incomplete = components.filter_map do |owner, operation, options, reports_cleanup|
          completed = owner.send(operation, **options)
          operation if reports_cleanup && !completed
        rescue StandardError => e
          handle_exception(e, level: :error, operation: "crypt.shutdown.#{operation}")
          operation
        end
        if incomplete.empty?
          log.info 'Legion::Crypt shutdown completed'
        else
          log.error "Legion::Crypt shutdown completed with incomplete Vault cleanup: #{incomplete.join(', ')}"
        end
      end

      def effective_cluster_configs
        clusters.empty? ? { nil => Legion::Settings[:crypt][:vault] } : clusters
      end

      def default_session
        @vault_sessions&.[](default_cluster_name)
      end

      def session_for(cluster_name)
        name = cluster_name.nil? ? default_cluster_name : cluster_name.to_sym
        @vault_sessions&.[](name)
      end

      def postgresql_leases_for_mode(leases:, mode:)
        role = POSTGRES_ROLE_MAP[mode]
        return leases unless role

        postgresql_key = leases.key?(:postgresql) ? :postgresql : 'postgresql'
        definition = leases[postgresql_key]
        return leases unless definition.is_a?(Hash)

        path_key = definition.key?(:path) ? :path : 'path'
        leases.merge(postgresql_key => definition.merge(path_key => "postgresql/creds/#{role}"))
      end

      def start_svid_rotation
        return unless Legion::Crypt::Spiffe.enabled?

        log.info 'Legion::Crypt starting SPIFFE SVID rotation'
        @svid_rotation = Legion::Crypt::Spiffe::SvidRotation.new
        @svid_rotation.start
      rescue IOError, SystemCallError, Timeout::Error, Legion::Crypt::Spiffe::Error => e
        handle_exception(e, level: :warn, operation: 'crypt.start_svid_rotation')
      end

      def stop_svid_rotation(deadline: nil)
        return unless @svid_rotation

        Legion::Crypt::Vault::Operation.with_timeout(deadline: deadline) { @svid_rotation.stop }
      ensure
        @svid_rotation = nil
      end

      # Reentrant so startup can activate Kerberos grants through the same login path as callers.
      def lifecycle_monitor
        @lifecycle_monitor ||= Monitor.new
      end
    end
  end
end
