# frozen_string_literal: true

# Ruby 4.0 freezes OpenSSL::SSL::SSLContext::DEFAULT_PARAMS by default.
# The vault gem (0.18.x) mutates this hash in Vault.setup! — replace it
# with a mutable dup so the require succeeds on Ruby 4.0+.
require 'legion/logging/helper'
require 'openssl'
if OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.frozen?
  unfrozen = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.dup
  OpenSSL::SSL::SSLContext.send(:remove_const, :DEFAULT_PARAMS)
  OpenSSL::SSL::SSLContext.const_set(:DEFAULT_PARAMS, unfrozen)
end

require 'vault'
require 'legion/crypt/vault_operation'

module Legion
  module Crypt
    module VaultCluster
      include Legion::Logging::Helper

      def vault_client(name = nil)
        name = resolve_cluster_name(name)
        client, previous = vault_clients_mutex.synchronize do
          return if Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping

          @vault_clients ||= {}
          entry = @vault_clients[name]
          signature = vault_client_signature(clusters[name])
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
      rescue ::Vault::HTTPError => e
        return true if e.message =~ /\b(429|472|473)\b/

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

      def vault_client_signature(config)
        return unless config.is_a?(Hash)

        namespace =
          if config.key?(:namespace)
            config[:namespace]
          elsif defined?(Legion::Settings)
            crypt_settings = Legion::Settings[:crypt]
            crypt_settings.respond_to?(:dig) ? crypt_settings.dig(:vault, :vault_namespace) : nil
          end
        {
          address: "#{config[:protocol]}://#{config[:address]}:#{config[:port]}",
          namespace: namespace, ssl_verify: resolve_cluster_ssl_verify(config[:tls]), token: config[:token]
        }
      end

      def build_vault_client(signature)
        log.info "Building Vault client address=#{signature[:address]} namespace=#{signature[:namespace].inspect} ssl_verify=#{signature[:ssl_verify]}"
        ::Vault::Client.new(**signature)
      end

      def retire_vault_client(client, deadline: nil)
        return unless client.respond_to?(:shutdown)

        Legion::Crypt::VaultOperation.with_timeout(deadline: deadline) do
          # vault-ruby shutdown requires a pool even when this client has not made a request.
          client.pool if client.respond_to?(:pool)
          client.shutdown
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.vault_cluster.retire_vault_client')
      end

      def resolve_cluster_ssl_verify(tls_config)
        return true if tls_config.nil?

        verify = tls_config[:verify]&.to_s
        verify != 'none'
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
