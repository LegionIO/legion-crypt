# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/vault_operation'
require 'uri'
require 'vault'

module Legion
  module Crypt
    module Vault
      include Legion::Logging::Helper

      attr_accessor :sessions

      def settings
        Legion::Settings[:crypt][:vault]
      end

      def connect_vault
        return unless start_session_tracking

        vault_settings = Legion::Settings[:crypt][:vault]
        ::Vault.address = resolve_vault_address(vault_settings)
        ::Vault.ssl_verify = resolve_ssl_verify(vault_settings[:tls])
        namespace = vault_settings[:vault_namespace]
        log.info "Vault connection requested address=#{::Vault.address} namespace=#{namespace || 'none'} ssl_verify=#{::Vault.ssl_verify}"

        Legion::Settings[:crypt][:vault][:token] = ENV['VAULT_DEV_ROOT_TOKEN_ID'] if ENV.key? 'VAULT_DEV_ROOT_TOKEN_ID'
        return nil if Legion::Settings[:crypt][:vault][:token].nil?

        ::Vault.token = Legion::Settings[:crypt][:vault][:token]
        ::Vault.namespace = namespace if namespace
        if vault_healthy?
          Legion::Settings[:crypt][:vault][:connected] = true
          log.info "Vault connected at #{::Vault.address} (namespace=#{namespace || 'none'})"
        end
      rescue StandardError => e
        log_vault_connection_error(e)
        Legion::Settings[:crypt][:vault][:connected] = false
        false
      end

      def vault_healthy?
        ::Vault.sys.health_status.initialized?
      rescue ::Vault::HTTPError => e
        # 429 = standby, 472 = DR secondary, 473 = performance standby
        # All indicate an initialized, healthy Vault — just not the active node.
        return true if e.message =~ /\b(429|472|473)\b/

        raise
      end

      def read(path, type = nil, cluster_name: nil)
        full_path = type.nil? || type.empty? ? path : "#{type}/#{path}"
        log_read_context(full_path, cluster_name: cluster_name)
        lease = logical_client(cluster_name: cluster_name).read(full_path)
        if lease.nil?
          log_vault_debug("Vault read: #{full_path} returned nil")
          return nil
        end
        add_session(path: lease.lease_id) if lease.respond_to?(:lease_id) && lease.lease_id && !lease.lease_id.empty?

        data = lease.data
        log_vault_debug("Vault read: #{full_path} returned keys=#{data&.keys&.inspect}")
        unwrap_kv_v2(data, full_path)
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.read', path: full_path)
        raise
      end

      def get(path, cluster_name: nil)
        log.debug "Vault kv get: path=#{path}"
        result = kv_client(cluster_name: cluster_name).read(path)
        if result.nil?
          log.debug "Vault kv get: #{path} returned nil"
          return nil
        end

        log.debug "Vault kv get: #{path} returned keys=#{result.data&.keys&.inspect}"
        result.data
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.get', path: path)
        raise
      end

      def write(path, cluster_name: nil, **hash)
        log.info "Vault kv write requested path=#{path}"
        kv_client(cluster_name: cluster_name).write(path, **hash)
        log.info "Vault kv write complete path=#{path}"
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.write', path: path)
        raise
      end

      def delete(path, cluster_name: nil)
        logical_client(cluster_name: cluster_name).delete(path)
        log.info "Vault delete complete path=#{path}"
        { success: true, path: path }
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.delete', path: path)
        { success: false, path: path, error: e.message }
      end

      def exist?(path, cluster_name: nil)
        !kv_client(cluster_name: cluster_name).read_metadata(path).nil?
      end

      def start_session_tracking
        session_mutex.synchronize do
          return false if crypt_stopping?

          @sessions = []
          @sessions_stopped = false
          @session_generation = (@session_generation || 0) + 1
        end
        true
      end

      def add_session(path:)
        session_mutex.synchronize do
          return if @sessions_stopped || crypt_stopping?

          (@sessions ||= []).push(path)
        end
      end

      def close_sessions(deadline: nil)
        deadline ||= ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + VaultOperation::SHUTDOWN_TIMEOUT
        pending = session_mutex.synchronize do
          @sessions_stopped = true
          @session_generation = (@session_generation || 0) + 1
          detached = @sessions || []
          @sessions = []
          detached
        end
        log.info 'Closing all Legion::Crypt vault sessions'
        closed = []
        pending.each do |session|
          break if ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) >= deadline

          VaultOperation.with_timeout(deadline: deadline) { close_session(session: session) }
          closed << session
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.vault.close_session')
        end
        closed
      end

      def shutdown_renewer
        renewer = session_mutex.synchronize do
          @sessions_stopped = true
          @session_generation = (@session_generation || 0) + 1
          detached = @renewer
          @renewer = nil
          detached
        end
        return if renewer.nil?

        log.info 'Shutting down Legion::Crypt::Vault::Renewer'
        renewer.cancel
      end

      def close_session(session:)
        ::Vault.sys.revoke(session)
      end

      def renew_session(session:)
        ::Vault.sys.renew(session)
      end

      def renew_sessions(**_opts)
        generation, pending = session_mutex.synchronize do
          return [] if @sessions_stopped || crypt_stopping?

          [@session_generation, (@sessions || []).dup]
        end
        log.debug 'Vault renewal cycle start'
        return renew_cluster_tokens(generation: generation) if respond_to?(:connected_clusters) && connected_clusters.any?

        renewed = []
        pending.each do |session|
          break unless session_maintenance_active?(generation)

          VaultOperation.with_timeout { renew_session(session: session) }
          renewed << session
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.vault.renew_session')
        end
        log.debug 'Vault renewal cycle complete'
        renewed
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.renew_sessions')
        raise
      end

      def renew_cluster_tokens(generation: session_mutex.synchronize { @session_generation })
        renewed = []
        connected_clusters.each_key do |name|
          break unless session_maintenance_active?(generation)

          VaultOperation.with_timeout { vault_client(name).auth_token.renew_self }
          renewed << name
          log.info "Vault token renewed for cluster #{name}"
        rescue StandardError => e
          log_vault_error(name, e)
        end
        renewed
      end

      def vault_exists?(name)
        ::Vault.sys.mounts.key?(name.to_sym)
      end

      private

      def session_mutex
        @session_mutex ||= Mutex.new
      end

      def crypt_stopping?
        Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping
      end

      def session_maintenance_active?(generation)
        session_mutex.synchronize do
          !@sessions_stopped && !crypt_stopping? && @session_generation == generation
        end
      end

      def kv_client(cluster_name: nil)
        mount = Legion::Settings[:crypt][:vault][:kv_path]
        if respond_to?(:connected_clusters) && connected_clusters.any?
          connected_vault_client(cluster_name).kv(mount)
        else
          raise ArgumentError, "Vault cluster not connected: #{cluster_name}" if cluster_name

          ::Vault.kv(mount)
        end
      end

      def logical_client(cluster_name: nil)
        if respond_to?(:connected_clusters) && connected_clusters.any?
          connected_vault_client(cluster_name).logical
        else
          raise ArgumentError, "Vault cluster not connected: #{cluster_name}" if cluster_name

          ::Vault.logical
        end
      end

      def log_read_context(full_path, cluster_name: nil)
        namespace = if respond_to?(:connected_clusters) && connected_clusters.any?
                      client = connected_vault_client(cluster_name)
                      client.respond_to?(:namespace) ? client.namespace : 'n/a'
                    else
                      'n/a (global client)'
                    end
        log.debug "Vault read: path=#{full_path}, namespace=#{namespace}"
      end

      def connected_vault_client(cluster_name = nil)
        selected_cluster = selected_connected_cluster_name(cluster_name)
        raise ArgumentError, "Vault cluster not connected: #{cluster_name}" if selected_cluster.nil? && cluster_name

        selected_cluster ? vault_client(selected_cluster) : nil
      end

      def unwrap_kv_v2(data, full_path)
        return data unless data.is_a?(Hash) && data.key?(:data) && data[:data].is_a?(Hash) && data.key?(:metadata)

        log_vault_debug("Vault read: #{full_path} detected KV v2 envelope, unwrapping :data key")
        data[:data]
      end

      def resolve_ssl_verify(tls_config)
        return true if tls_config.nil?

        verify = tls_config[:verify]&.to_s
        verify != 'none'
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

      def log_vault_connection_error(error)
        handle_exception(error, level: :error, operation: 'crypt.vault.connect_vault', address: ::Vault.address)
      end

      def log_vault_debug(message)
        log.debug(message)
      end
    end
  end
end
