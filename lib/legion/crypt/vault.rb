# frozen_string_literal: true

require 'uri'
require 'vault'

module Legion
  module Crypt
    module Vault
      attr_accessor :sessions

      def settings
        Legion::Settings[:crypt][:vault]
      end

      def connect_vault
        @sessions = []
        vault_settings = Legion::Settings[:crypt][:vault]
        protocol = vault_settings[:protocol] || 'http'
        address  = vault_settings[:address] || 'localhost'
        port     = vault_settings[:port] || 8200

        if address.match?(%r{\Ahttps?://})
          uri = URI.parse(address)
          protocol = uri.scheme
          address  = uri.host
          port     = uri.port if vault_settings[:port].nil?
        end

        ::Vault.address = "#{protocol}://#{address}:#{port}"

        Legion::Settings[:crypt][:vault][:token] = ENV['VAULT_DEV_ROOT_TOKEN_ID'] if ENV.key? 'VAULT_DEV_ROOT_TOKEN_ID'
        return nil if Legion::Settings[:crypt][:vault][:token].nil?

        ::Vault.token = Legion::Settings[:crypt][:vault][:token]
        if vault_healthy?
          Legion::Settings[:crypt][:vault][:connected] = true
          Legion::Logging.info "Vault connected at #{::Vault.address}" if defined?(Legion::Logging)
        end
      rescue StandardError => e
        if defined?(Legion::Logging) && Legion::Logging.respond_to?(:log_exception)
          Legion::Logging.log_exception(e, lex: 'crypt', component_type: :helper)
        elsif defined?(Legion::Logging) && Legion::Logging.respond_to?(:error)
          Legion::Logging.error "Vault connection failed: #{e.class}=#{e.message}\n#{Array(e.backtrace).first(10).join("\n")}"
        else
          warn "Vault connection failed: #{e.class}=#{e.message}"
        end
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

      def read(path, type = 'legion')
        full_path = type.nil? || type.empty? ? "#{type}/#{path}" : path
        log_read_context(full_path)
        lease = logical_client.read(full_path)
        if lease.nil?
          log_vault_debug("Vault read: #{full_path} returned nil")
          return nil
        end
        add_session(path: lease.lease_id) if lease.respond_to?(:lease_id) && lease.lease_id && !lease.lease_id.empty?

        data = lease.data
        log_vault_debug("Vault read: #{full_path} returned keys=#{data&.keys&.inspect}")
        unwrap_kv_v2(data, full_path)
      rescue StandardError => e
        Legion::Logging.warn "Vault read failed at #{full_path}: #{e.class}=#{e.message}" if defined?(Legion::Logging)
        raise
      end

      def get(path)
        Legion::Logging.debug "Vault kv get: path=#{path}" if defined?(Legion::Logging)
        result = kv_client.read(path)
        if result.nil?
          Legion::Logging.debug "Vault kv get: #{path} returned nil" if defined?(Legion::Logging)
          return nil
        end

        Legion::Logging.debug "Vault kv get: #{path} returned keys=#{result.data&.keys&.inspect}" if defined?(Legion::Logging)
        result.data
      rescue StandardError => e
        Legion::Logging.warn "Vault kv get failed at #{path}: #{e.class}=#{e.message}" if defined?(Legion::Logging)
        raise
      end

      def write(path, **hash)
        Legion::Logging.debug "Vault kv write: #{path}" if defined?(Legion::Logging)
        kv_client.write(path, **hash)
      rescue StandardError => e
        Legion::Logging.warn "Vault kv write failed at #{path}: #{e.message}" if defined?(Legion::Logging)
        raise
      end

      def delete(path)
        logical_client.delete(path)
        { success: true, path: path }
      rescue StandardError => e
        Legion::Logging.warn "Vault delete failed for #{path}: #{e.message}" if defined?(Legion::Logging)
        { success: false, path: path, error: e.message }
      end

      def exist?(path)
        !kv_client.read_metadata(path).nil?
      end

      def add_session(path:)
        @sessions ||= []
        @sessions.push(path)
      end

      def close_sessions
        return if @sessions.nil?

        Legion::Logging.info 'Closing all Legion::Crypt vault sessions'

        @sessions.each do |session|
          close_session(session: session)
        end
      end

      def shutdown_renewer
        return unless Legion::Settings[:crypt][:vault][:connected]
        return if @renewer.nil?

        Legion::Logging.debug 'Shutting down Legion::Crypt::Vault::Renewer'
        @renewer.cancel
      end

      def close_session(session:)
        ::Vault.sys.revoke(session)
      end

      def renew_session(session:)
        ::Vault.sys.renew(session)
      end

      def renew_sessions(**_opts)
        Legion::Logging.debug 'Vault renewal cycle start' if defined?(Legion::Logging)
        result = if respond_to?(:connected_clusters) && connected_clusters.any?
                   renew_cluster_tokens
                 else
                   @sessions.each do |session|
                     renew_session(session: session)
                   end
                 end
        Legion::Logging.debug 'Vault renewal cycle complete' if defined?(Legion::Logging)
        result
      end

      def renew_cluster_tokens
        connected_clusters.each_key do |name|
          client = vault_client(name)
          client.auth_token.renew_self
          Legion::Logging.info "Vault token renewed for cluster #{name}" if defined?(Legion::Logging)
        rescue StandardError => e
          log_vault_error(name, e)
        end
      end

      def vault_exists?(name)
        ::Vault.sys.mounts.key?(name.to_sym)
      end

      private

      def kv_client
        if respond_to?(:connected_clusters) && connected_clusters.any?
          vault_client.kv(settings[:vault][:kv_path])
        else
          ::Vault.kv(settings[:vault][:kv_path])
        end
      end

      def logical_client
        if respond_to?(:connected_clusters) && connected_clusters.any?
          vault_client.logical
        else
          ::Vault.logical
        end
      end

      def log_read_context(full_path)
        return unless defined?(Legion::Logging)

        namespace = if respond_to?(:connected_clusters) && connected_clusters.any?
                      client = vault_client
                      client.respond_to?(:namespace) ? client.namespace : 'n/a'
                    else
                      'n/a (global client)'
                    end
        Legion::Logging.debug "Vault read: path=#{full_path}, namespace=#{namespace}"
      end

      def unwrap_kv_v2(data, full_path)
        return data unless data.is_a?(Hash) && data.key?(:data) && data[:data].is_a?(Hash) && data.key?(:metadata)

        log_vault_debug("Vault read: #{full_path} detected KV v2 envelope, unwrapping :data key")
        data[:data]
      end

      def log_vault_debug(message)
        Legion::Logging.debug(message) if defined?(Legion::Logging)
      end
    end
  end
end
