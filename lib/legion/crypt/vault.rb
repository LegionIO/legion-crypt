# frozen_string_literal: true

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
        ::Vault.address = "#{Legion::Settings[:crypt][:vault][:protocol]}://#{Legion::Settings[:crypt][:vault][:address]}:#{Legion::Settings[:crypt][:vault][:port]}" # rubocop:disable Layout/LineLength

        Legion::Settings[:crypt][:vault][:token] = ENV['VAULT_DEV_ROOT_TOKEN_ID'] if ENV.key? 'VAULT_DEV_ROOT_TOKEN_ID'
        return nil if Legion::Settings[:crypt][:vault][:token].nil?

        ::Vault.token = Legion::Settings[:crypt][:vault][:token]
        Legion::Settings[:crypt][:vault][:connected] = true if ::Vault.sys.health_status.initialized?
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
        lease = ::Vault.logical.read(full_path)
        add_session(path: lease.lease_id) if lease.respond_to? :lease_id
        lease.data
      end

      def get(path)
        result = ::Vault.kv(settings[:vault][:kv_path]).read(path)
        return nil if result.nil?

        result.data
      end

      def write(path, **hash)
        ::Vault.kv(settings[:vault][:kv_path]).write(path, **hash)
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
        @sessions.each do |session|
          renew_session(session: session)
        end
      end

      def vault_exists?(name)
        ::Vault.sys.mounts.key?(name.to_sym)
      end
    end
  end
end
