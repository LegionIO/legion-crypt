# frozen_string_literal: true

require 'vault'

module Legion
  module Crypt
    module VaultCluster
      def vault_client(name = nil)
        name = resolve_cluster_name(name)
        @vault_clients ||= {}
        @vault_clients[name] ||= build_vault_client(clusters[name])
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
        clusters.select { |_, config| config[:token] && config[:connected] }
      end

      def connect_all_clusters
        results = {}
        clusters.each do |name, config|
          next unless config[:token]

          client = vault_client(name)
          config[:connected] = client.sys.health_status.initialized?
          results[name] = config[:connected]
          Legion::Logging.info "Vault cluster connected: #{name} at #{config[:address]}" if config[:connected] && defined?(Legion::Logging)
        rescue StandardError => e
          config[:connected] = false
          results[name] = false
          log_vault_error(name, e)
        end
        results
      end

      private

      def resolve_cluster_name(name)
        return name.to_sym if name

        default_cluster_name
      end

      def build_vault_client(config)
        return nil unless config.is_a?(Hash)

        client = ::Vault::Client.new(
          address: "#{config[:protocol]}://#{config[:address]}:#{config[:port]}",
          token:   config[:token]
        )
        client.namespace = config[:namespace] if config[:namespace]
        client
      end

      def log_vault_error(name, error)
        if defined?(Legion::Logging)
          Legion::Logging.error("Vault cluster #{name}: #{error.message}")
        else
          warn("Vault cluster #{name}: #{error.message}")
        end
      end
    end
  end
end
