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
        if ::Vault.sys.health_status.initialized?
          Legion::Settings[:crypt][:vault][:connected] = true
          Legion::Logging.info "Vault connected at #{::Vault.address}" if defined?(Legion::Logging)
        end
        return unless Legion.const_defined? 'Extensions::Actors::Every'

        require_relative 'vault_renewer'
        @renewer = Legion::Crypt::Vault::Renewer.new
      rescue StandardError => e
        Legion::Logging.error e.message
        Legion::Settings[:crypt][:vault][:connected] = false
        false
      end

      def read(path, type = 'legion')
        full_path = type.nil? || type.empty? ? "#{type}/#{path}" : path
        Legion::Logging.debug "Vault read: #{full_path}" if defined?(Legion::Logging)
        lease = ::Vault.logical.read(full_path)
        add_session(path: lease.lease_id) if lease.respond_to? :lease_id
        lease.data
      rescue StandardError => e
        Legion::Logging.warn "Vault read failed at #{full_path}: #{e.message}" if defined?(Legion::Logging)
        raise
      end

      def get(path)
        Legion::Logging.debug "Vault kv get: #{path}" if defined?(Legion::Logging)
        result = ::Vault.kv(settings[:vault][:kv_path]).read(path)
        return nil if result.nil?

        result.data
      rescue StandardError => e
        Legion::Logging.warn "Vault kv get failed at #{path}: #{e.message}" if defined?(Legion::Logging)
        raise
      end

      def write(path, **hash)
        Legion::Logging.debug "Vault kv write: #{path}" if defined?(Legion::Logging)
        ::Vault.kv(settings[:vault][:kv_path]).write(path, **hash)
      rescue StandardError => e
        Legion::Logging.warn "Vault kv write failed at #{path}: #{e.message}" if defined?(Legion::Logging)
        raise
      end

      def exist?(path)
        !::Vault.kv(settings[:vault][:kv_path]).read_metadata(path).nil?
      end

      def add_session(path:)
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
    end
  end
end
