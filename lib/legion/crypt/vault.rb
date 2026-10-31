# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/vault_operation'
require 'legion/crypt/vault_client'

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

        configuration = Legion::Settings[:crypt][:vault]
        configuration[:token] = ENV['VAULT_DEV_ROOT_TOKEN_ID'] if ENV.key? 'VAULT_DEV_ROOT_TOKEN_ID'
        return nil if configuration[:token].nil?

        client = vault_client
        log.info "Vault connection requested address=#{client.address} namespace=#{client.namespace || 'none'} ssl_verify=#{client.ssl_verify}"
        if vault_healthy?
          configuration[:connected] = true
          log.info "Vault connected at #{client.address} (namespace=#{client.namespace || 'none'})"
        end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.connect_vault')
        Legion::Settings[:crypt][:vault][:connected] = false
        false
      end

      def vault_healthy?
        vault_client.sys.health_status.initialized?
      rescue Legion::Crypt::Vault::HTTPError => e
        # 429 = standby, 472 = DR secondary, 473 = performance standby
        # All indicate an initialized, healthy Vault — just not the active node.
        return true if [429, 472, 473].include?(e.code)

        raise
      end

      def read(path, type = nil, cluster_name: nil)
        full_path = type.nil? || type.empty? ? path : "#{type}/#{path}"
        log_read_context(full_path, cluster_name: cluster_name)
        lease = logical_client(cluster_name: cluster_name).read(path: full_path)
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
        result = kv_client(cluster_name: cluster_name).read(path: path)
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
        kv_client(cluster_name: cluster_name).write(path: path, data: hash)
        log.info "Vault kv write complete path=#{path}"
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.write', path: path)
        raise
      end

      def delete(path, cluster_name: nil)
        logical_client(cluster_name: cluster_name).delete(path: path)
        log.info "Vault delete complete path=#{path}"
        { success: true, path: path }
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.delete', path: path)
        { success: false, path: path, error: e.message }
      end

      def exist?(path, cluster_name: nil)
        !kv_client(cluster_name: cluster_name).read_metadata(path: path).nil?
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
        vault_client.sys.revoke(lease_id: session)
      end

      def renew_session(session:)
        vault_client.sys.renew(lease_id: session)
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
          break unless session_maintenance_active?(generation: generation)

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
          break unless session_maintenance_active?(generation: generation)

          VaultOperation.with_timeout { vault_client(name).auth_token.renew_self }
          renewed << name
          log.info "Vault token renewed for cluster #{name}"
        rescue StandardError => e
          log_vault_error(name, e)
        end
        renewed
      end

      def vault_exists?(name)
        vault_client.sys.mounts.key?(name.to_sym)
      end

      private

      def session_mutex
        @session_mutex ||= Mutex.new
      end

      def crypt_stopping?
        Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping
      end

      def session_maintenance_active?(generation:, **)
        session_mutex.synchronize do
          !@sessions_stopped && !crypt_stopping? && @session_generation == generation
        end
      end

      def kv_client(cluster_name: nil)
        mount = Legion::Settings[:crypt][:vault][:kv_path]
        if respond_to?(:connected_clusters) && (clusters.any? || connected_clusters.any?)
          connected_vault_client(cluster_name).kv(mount: mount)
        else
          raise ArgumentError, "Vault cluster not connected: #{cluster_name}" if cluster_name

          vault_client.kv(mount: mount)
        end
      end

      def logical_client(cluster_name: nil)
        if respond_to?(:connected_clusters) && (clusters.any? || connected_clusters.any?)
          connected_vault_client(cluster_name).logical
        else
          raise ArgumentError, "Vault cluster not connected: #{cluster_name}" if cluster_name

          vault_client.logical
        end
      end

      def log_read_context(full_path, cluster_name: nil)
        namespace = if respond_to?(:connected_clusters) && connected_clusters.any?
                      client = connected_vault_client(cluster_name)
                      client.respond_to?(:namespace) ? client.namespace : 'n/a'
                    else
                      vault_client.namespace
                    end
        log.debug "Vault read: path=#{full_path}, namespace=#{namespace}"
      end

      def connected_vault_client(cluster_name = nil)
        selected_cluster = selected_connected_cluster_name(cluster_name)
        raise ArgumentError, "Vault cluster not connected: #{cluster_name || default_cluster_name}" if selected_cluster.nil?

        vault_client(selected_cluster)
      end

      def unwrap_kv_v2(data, full_path)
        return data unless data.is_a?(Hash) && data.key?(:data) && data[:data].is_a?(Hash) && data.key?(:metadata)

        log_vault_debug("Vault read: #{full_path} detected KV v2 envelope, unwrapping :data key")
        data[:data]
      end

      def log_vault_debug(message)
        log.debug(message)
      end
    end
  end
end
