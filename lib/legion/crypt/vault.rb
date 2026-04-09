# frozen_string_literal: true

require 'legion/logging/helper'
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
        @sessions = []
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

      def add_session(path:)
        @sessions ||= []
        @sessions.push(path)
      end

      def close_sessions
        return if @sessions.nil?

        log.info 'Closing all Legion::Crypt vault sessions'

        @sessions.each do |session|
          close_session(session: session)
        end
      end

      def shutdown_renewer
        return unless Legion::Settings[:crypt][:vault][:connected]
        return if @renewer.nil?

        log.info 'Shutting down Legion::Crypt::Vault::Renewer'
        @renewer.cancel
      end

      def close_session(session:)
        ::Vault.sys.revoke(session)
      end

      def renew_session(session:)
        ::Vault.sys.renew(session)
      end

      def renew_sessions(**_opts)
        log.debug 'Vault renewal cycle start'
        result = if respond_to?(:connected_clusters) && connected_clusters.any?
                   renew_cluster_tokens
                 else
                   @sessions.each do |session|
                     renew_session(session: session)
                   end
                 end
        log.debug 'Vault renewal cycle complete'
        result
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.vault.renew_sessions')
        raise
      end

      def renew_cluster_tokens
        connected_clusters.each_key do |name|
          client = vault_client(name)
          client.auth_token.renew_self
          log.info "Vault token renewed for cluster #{name}"
        rescue StandardError => e
          log_vault_error(name, e)
        end
      end

      def vault_exists?(name)
        ::Vault.sys.mounts.key?(name.to_sym)
      end

      private

      def kv_client(cluster_name: nil)
        if respond_to?(:connected_clusters) && connected_clusters.any?
          connected_vault_client(cluster_name).kv(settings[:kv_path])
        else
          raise ArgumentError, "Vault cluster not connected: #{cluster_name}" if cluster_name

          ::Vault.kv(settings[:kv_path])
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
