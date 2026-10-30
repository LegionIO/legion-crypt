# frozen_string_literal: true

require 'legion/logging/helper'
require 'uri'
require 'legion/crypt/vault_client'
require 'legion/crypt/tls'
require 'legion/crypt/vault_operation'

module Legion
  module Crypt
    module VaultCluster
      include Legion::Logging::Helper

      def vault_client(name = nil)
        name = resolve_cluster_name(name)
        client, previous = vault_clients_mutex.synchronize do
          return @vault_clients&.dig(name, :client) if Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping

          @vault_clients ||= {}
          entry = @vault_clients[name]
          config = name.nil? ? vault_settings : clusters[name]
          signature = vault_client_signature(config)
          if current_vault_client?(entry, signature)
            entry[:signature][:token] = signature[:token]&.dup if entry[:signature][:token] != signature[:token]
            return entry[:client]
          end

          replacement = signature && build_vault_client(signature)
          @vault_clients.delete(name)
          if replacement
            signature.transform_values! { |value| value.is_a?(String) ? value.dup.freeze : value }
            @vault_clients[name] = { client: replacement, signature: signature }
          end
          [replacement, entry&.fetch(:client)]
        end
        retire_vault_client(previous) if previous
        client
      end

      def clear_vault_clients(deadline: nil)
        deadline ||= ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + Legion::Crypt::VaultOperation::SHUTDOWN_TIMEOUT
        entries = vault_clients_mutex.synchronize do
          previous = @vault_clients || {}
          @vault_clients = {}
          previous.values
        end
        entries.each { |entry| retire_vault_client(entry[:client], deadline: deadline) }
      end

      def cluster(name = nil)
        name = resolve_cluster_name(name)
        clusters[name]
      end

      def default_cluster_name
        name = vault_settings[:default]
        name ? name.to_sym : clusters.keys.first
      end

      def clusters
        vault_settings[:clusters] || {}
      end

      def connected_clusters
        now = Time.now
        clusters.select do |_, config|
          config[:token] && config[:connected] && !config[:relogin_required] &&
            (!config[:expires_at] || config[:expires_at] > now)
        end
      end

      def connect_all_clusters
        log.info "Vault cluster connect requested configured_clusters=#{clusters.size}"
        log_vault_debug("connect_all_clusters: #{clusters.size} cluster(s) configured")
        results = {}
        clusters.each do |name, config|
          log_vault_debug("connect_all_clusters: #{name} (auth_method=#{config[:auth_method].inspect})")
          case config[:auth_method]&.to_s
          when 'kerberos'
            results[name] = connect_kerberos_cluster(name, config)
          when 'ldap'
            next # handled by ldap_login_all
          else
            next unless config[:token]

            client = vault_client(name)
            config[:connected] = cluster_healthy?(client)
            results[name] = config[:connected]
            log_cluster_connected(name, config) if config[:connected]
          end
        rescue StandardError => e
          config[:connected] = false
          results[name] = false
          log_vault_error(name, e, operation: 'crypt.vault_cluster.connect_all_clusters')
        end

        connected = results.select { |_, v| v }
        log.info "Vault cluster connect complete connected=#{connected.size} attempted=#{results.size}"
        log_vault_debug("connect_all_clusters: #{connected.size}/#{results.size} connected")
        sync_vault_connected(connected.any?)
        results
      end

      private

      def cluster_healthy?(client)
        client.sys.health_status.initialized?
      rescue Legion::Crypt::Vault::HTTPError => e
        return true if [429, 472, 473].include?(e.code)

        handle_exception(e, level: :warn, operation: 'crypt.vault_cluster.cluster_healthy')
        raise
      end

      def sync_vault_connected(connected)
        return unless defined?(Legion::Settings)

        Legion::Settings[:crypt][:vault][:connected] = connected
      end

      def selected_connected_cluster_name(name = nil)
        active_clusters = connected_clusters
        return nil if active_clusters.empty?

        if name
          cluster_name = name.to_sym
          raise ArgumentError, "Vault cluster not connected: #{cluster_name}" unless active_clusters.key?(cluster_name)

          return cluster_name
        end

        default_name = vault_settings[:default]&.to_sym
        return default_name if default_name && active_clusters.key?(default_name)

        active_clusters.keys.first
      end

      def resolve_cluster_name(name)
        return name.to_sym if name

        default_cluster_name
      end

      def vault_clients_mutex
        @vault_clients_mutex ||= Mutex.new
      end

      def current_vault_client?(entry, signature)
        return false unless entry && signature
        return false unless entry[:signature].all? { |key, value| key == :token || value == signature[key] }

        entry[:signature][:token] == signature[:token] || entry[:client].token == signature[:token]
      end

      def resolve_vault_address(vault_settings)
        protocol = vault_settings[:protocol] || 'http'
        address  = vault_settings[:address] || 'localhost'
        port     = vault_settings[:port] || 8200

        if address.match?(%r{\Ahttps?://})
          uri = URI.parse(address)
          protocol = uri.scheme
          address  = uri.host
          port     = uri.port if vault_settings[:port].nil?
        end

        "#{protocol}://#{address}:#{port}"
      end

      def vault_client_signature(config)
        return unless config.is_a?(Hash)

        tls = Legion::Crypt::TLS.migrate_legacy(config[:tls] || {})
        verify = %w[none mutual].include?(tls[:verify].to_s) ? tls[:verify].to_s : 'peer'

        namespace =
          if config.key?(:namespace)
            config[:namespace]
          elsif defined?(Legion::Settings)
            crypt_settings = Legion::Settings[:crypt]
            crypt_settings.respond_to?(:dig) ? crypt_settings.dig(:vault, :vault_namespace) : nil
          end
        {
          address: resolve_vault_address(config), namespace: namespace, token: config[:token],
          verify: verify, ca: tls[:ca], cert: tls[:cert], key: tls[:key],
          timeout: vault_settings[:operation_timeout] || Legion::Crypt::VaultOperation::DEFAULT_TIMEOUT
        }
      end

      def build_vault_client(signature)
        tls = Legion::Crypt::TLS.resolve(signature.slice(:verify, :ca, :cert, :key))
        options = signature.slice(:address, :namespace, :token, :timeout).merge(tls: tls)
        log.info "Building Vault client address=#{options[:address]} namespace=#{options[:namespace].inspect} tls_verify=#{tls[:verify]}"
        Legion::Crypt::VaultClient.new(**options)
      end

      def retire_vault_client(client, deadline: nil)
        return unless client.respond_to?(:shutdown)

        Legion::Crypt::VaultOperation.with_timeout(deadline: deadline) do
          client.shutdown
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.vault_cluster.retire_vault_client')
      end

      def log_vault_error(name, error, operation: 'crypt.vault_cluster.error')
        handle_exception(error, level: :error, operation: operation, cluster_name: name)
      end

      def connect_kerberos_cluster(name, config)
        krb_config = config[:kerberos] || {}
        spn = krb_config[:service_principal]
        auth_path = krb_config[:auth_path] || Legion::Crypt::KerberosAuth::DEFAULT_AUTH_PATH

        log_vault_debug("connect_kerberos_cluster[#{name}]: SPN=#{spn}, auth_path=#{auth_path}, namespace=#{config[:namespace].inspect}")

        unless spn
          log_vault_warn(name, 'Kerberos auth missing service_principal, skipping')
          config[:connected] = false
          return false
        end

        require 'legion/crypt/kerberos_auth'
        client = vault_client(name)
        log_vault_debug("connect_kerberos_cluster[#{name}]: client.namespace=#{client.respond_to?(:namespace) ? client.namespace.inspect : 'n/a'}")
        log.info "Connecting Vault cluster #{name} via Kerberos auth_path=#{auth_path}"

        result = Legion::Crypt::KerberosAuth.login(
          vault_client:      client,
          service_principal: spn,
          auth_path:         auth_path
        )

        config[:token] = result[:token]
        config[:lease_duration] = result[:lease_duration]
        config[:renewable] = result[:renewable]
        config[:connected] = true
        ttl = result[:lease_duration].to_f
        config[:expires_at] = ttl.positive? ? Time.now + ttl : nil
        config[:relogin_required] = false
        client.token = result[:token]
        log_vault_debug("connect_kerberos_cluster[#{name}]: policies=#{result[:policies].inspect}")
        log_cluster_connected(name, config)
        true
      rescue Legion::Crypt::KerberosAuth::GemMissingError => e
        handle_exception(e, level: :warn, operation: 'crypt.vault_cluster.connect_kerberos_cluster', cluster_name: name)
        log_vault_warn(name, e.message)
        config[:connected] = false
        false
      rescue Legion::Crypt::KerberosAuth::AuthError => e
        handle_exception(e, level: :warn, operation: 'crypt.vault_cluster.connect_kerberos_cluster', cluster_name: name)
        log_vault_warn(name, "Kerberos auth failed: #{e.message}")
        config[:connected] = false
        false
      end

      def log_cluster_connected(name, config)
        log.info "Vault cluster connected: #{name} at #{config[:address]}"
      end

      def log_vault_warn(name, message)
        log.warn("Vault cluster #{name}: #{message}")
      end

      def log_vault_debug(message)
        log.debug(message)
      end
    end
  end
end
