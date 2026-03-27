# frozen_string_literal: true

# Ruby 4.0 freezes OpenSSL::SSL::SSLContext::DEFAULT_PARAMS by default.
# The vault gem (0.18.x) mutates this hash in Vault.setup! — replace it
# with a mutable dup so the require succeeds on Ruby 4.0+.
require 'openssl'
if OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.frozen?
  unfrozen = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.dup
  OpenSSL::SSL::SSLContext.send(:remove_const, :DEFAULT_PARAMS)
  OpenSSL::SSL::SSLContext.const_set(:DEFAULT_PARAMS, unfrozen)
end

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
          case config[:auth_method]&.to_s
          when 'kerberos'
            results[name] = connect_kerberos_cluster(name, config)
          when 'ldap'
            next # handled by ldap_login_all
          else
            next unless config[:token]

            client = vault_client(name)
            config[:connected] = client.sys.health_status.initialized?
            results[name] = config[:connected]
            log_cluster_connected(name, config) if config[:connected]
          end
        rescue StandardError => e
          config[:connected] = false
          results[name] = false
          log_vault_error(name, e)
        end

        mark_vault_connected if results.any? { |_, v| v }
        results
      end

      private

      def mark_vault_connected
        return unless defined?(Legion::Settings)

        Legion::Settings[:crypt][:vault][:connected] = true
      end

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
        namespace =
          if config.key?(:namespace)
            config[:namespace]
          elsif defined?(Legion::Settings)
            crypt_settings = Legion::Settings[:crypt]
            crypt_settings.respond_to?(:dig) ? crypt_settings.dig(:vault, :vault_namespace) : nil
          end
        client.namespace = namespace if namespace
        client
      end

      def log_vault_error(name, error)
        if defined?(Legion::Logging)
          Legion::Logging.error("Vault cluster #{name}: #{error.message}")
        else
          warn("Vault cluster #{name}: #{error.message}")
        end
      end

      def connect_kerberos_cluster(name, config)
        krb_config = config[:kerberos] || {}
        spn = krb_config[:service_principal]

        unless spn
          log_vault_warn(name, 'Kerberos auth missing service_principal, skipping')
          config[:connected] = false
          return false
        end

        require 'legion/crypt/kerberos_auth'
        result = Legion::Crypt::KerberosAuth.login(
          vault_client:      vault_client(name),
          service_principal: spn,
          auth_path:         krb_config[:auth_path] || Legion::Crypt::KerberosAuth::DEFAULT_AUTH_PATH
        )

        config[:token] = result[:token]
        config[:lease_duration] = result[:lease_duration]
        config[:renewable] = result[:renewable]
        config[:connected] = true
        vault_client(name).token = result[:token]
        log_cluster_connected(name, config)
        true
      rescue Legion::Crypt::KerberosAuth::GemMissingError => e
        log_vault_warn(name, e.message)
        config[:connected] = false
        false
      rescue Legion::Crypt::KerberosAuth::AuthError => e
        log_vault_warn(name, "Kerberos auth failed: #{e.message}")
        config[:connected] = false
        false
      end

      def log_cluster_connected(name, config)
        Legion::Logging.info "Vault cluster connected: #{name} at #{config[:address]}" if defined?(Legion::Logging)
      end

      def log_vault_warn(name, message)
        if defined?(Legion::Logging)
          Legion::Logging.warn("Vault cluster #{name}: #{message}")
        else
          warn("Vault cluster #{name}: #{message}")
        end
      end
    end
  end
end
