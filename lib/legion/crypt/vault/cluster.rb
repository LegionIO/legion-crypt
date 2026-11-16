# frozen_string_literal: true

require 'legion/logging/helper'
require 'uri'
require 'legion/crypt/vault/client'
require 'legion/crypt/tls'
require 'legion/crypt/vault/operation'

module Legion
  module Crypt
    module Vault
      class GrantRejectedError < RuntimeError; end

      module Cluster
        include Legion::Logging::Helper

        def vault_client(name = nil)
          name = resolve_cluster_name(name)
          loop do
            candidate = accepted = nil
            signature, generation = vault_clients_mutex.synchronize do
              return @vault_clients&.dig(name, :client) if Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping

              @vault_clients ||= {}
              entry = @vault_clients[name]
              signature = vault_client_signature(config: name.nil? ? Legion::Settings[:crypt][:vault] : clusters[name])
              cached = cached_vault_client(entry: entry, signature: signature)
              return cached if cached

              unless signature
                (@retired_vault_clients ||= ObjectSpace::WeakMap.new)[entry[:client]] = true if entry
                @vault_clients.delete(name)
                return nil
              end
              signature.transform_values! { |value| value.is_a?(String) ? value.dup.freeze : value }
              [signature, @vault_client_generation || 0]
            end
            candidate = build_vault_client(signature, name: name)
            accepted = install_vault_client(name: name, signature: signature, client: candidate, generation: generation)
            return accepted if accepted
          ensure
            retire_vault_client(client: candidate) unless accepted.equal?(candidate)
          end
        end

        # Resolves the configuration by cluster name so settings rebuilds do not reject the grant.
        def publish_vault_grant(cluster_name:, client:, grant:, auth_method:, issued_at: Time.now, current_token: nil, **)
          token = grant.fetch(:token)
          ttl = grant[:lease_duration].to_f
          expires_at = issued_at + ttl if ttl.positive?
          vault_clients_mutex.synchronize do
            config = cluster_name.nil? ? Legion::Settings[:crypt][:vault] : clusters[cluster_name]
            entry = @vault_clients&.[](cluster_name)
            unless entry && entry[:client].equal?(client) && current_vault_client?(entry: entry, signature: vault_client_signature(config: config))
              raise Legion::Crypt::Vault::GrantRejectedError, 'Vault client configuration changed during authentication'
            end
            raise Legion::Crypt::Vault::GrantRejectedError, 'Vault token changed during authentication' if current_token && config[:token] != current_token

            client.token = token
            connected = expires_at.nil? || expires_at > Time.now
            config.merge!(token: token, lease_duration: grant[:lease_duration], renewable: grant[:renewable],
                          expires_at: expires_at, connected: connected, relogin_required: !connected, auth_method: auth_method)
            entry[:signature][:token] = token.dup.freeze
            sync_vault_connected
          end
          expires_at
        end

        def disconnect_vault_grant(cluster_name:, token:, relogin_required:, **)
          vault_clients_mutex.synchronize do
            config = cluster_name.nil? ? Legion::Settings[:crypt][:vault] : clusters[cluster_name]
            next false unless config && config[:token] == token

            config.merge!(connected: false, relogin_required: relogin_required)
            sync_vault_connected
            true
          end
        end

        # Uses a separate client so the token is revoked with its own credentials, not the client's current token.
        def revoke_vault_token(client:, token:, deadline: nil, **)
          revoker = Legion::Crypt::Vault::Client.new(
            address: client.address, namespace: client.namespace, token: token, timeout: client.timeout,
            tls: { verify: client.ssl_verify, ca: client.ca, cert: client.cert, key: client.key }
          )
          Legion::Crypt::Vault::Operation.with_timeout(deadline: deadline) { revoker.auth_token.revoke_self }
        ensure
          revoker&.shutdown
        end

        def clear_vault_clients(deadline: nil, **)
          deadline ||= ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + Legion::Crypt::Vault::Operation::SHUTDOWN_TIMEOUT
          clients = vault_clients_mutex.synchronize do
            @vault_client_generation = (@vault_client_generation || 0) + 1
            previous = (@vault_clients || {}).values.map { |entry| entry[:client] }
            previous.concat(@retired_vault_clients.keys) if @retired_vault_clients
            @vault_clients = {}
            @retired_vault_clients = nil
            previous.uniq
          end
          clients.each { |client| retire_vault_client(client: client, deadline: deadline) }
        end

        def cluster(name = nil)
          name = resolve_cluster_name(name)
          clusters[name]
        end

        def default_cluster_name
          name = Legion::Settings[:crypt][:vault][:default]
          name ? name.to_sym : clusters.keys.first
        end

        def clusters
          Legion::Settings[:crypt][:vault][:clusters]
        end

        def connected_clusters
          vault_clients_mutex.synchronize { connected_cluster_configs }
        end

        private

        # Caller holds vault_clients_mutex.
        def connected_cluster_configs
          now = Time.now
          clusters.select do |_, config|
            config[:token] && config[:connected] && !config[:relogin_required] &&
              (!config[:expires_at] || config[:expires_at] > now)
          end
        end

        # Caller holds vault_clients_mutex. LegionIO and extensions read the top-level flag directly,
        # so named clusters keep it current; a single cluster publishes straight into the top level.
        def sync_vault_connected
          Legion::Settings[:crypt][:vault][:connected] = connected_cluster_configs.any? unless clusters.empty?
        end

        def selected_connected_cluster_name(name = nil)
          active_clusters = connected_clusters
          return nil if active_clusters.empty?

          if name
            cluster_name = name.to_sym
            raise ArgumentError, "Vault cluster not connected: #{cluster_name}" unless active_clusters.key?(cluster_name)

            return cluster_name
          end

          default_name = Legion::Settings[:crypt][:vault][:default]&.to_sym
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

        def current_vault_client?(entry:, signature:, **)
          return false unless entry && signature
          return false unless entry[:signature].all? { |key, value| key == :token || value == signature[key] }

          entry[:signature][:token] == signature[:token] || entry[:client].token == signature[:token]
        end

        def cached_vault_client(entry:, signature:, **)
          return unless current_vault_client?(entry: entry, signature: signature)

          entry[:signature][:token] = signature[:token]&.dup if entry[:signature][:token] != signature[:token]
          entry[:client]
        end

        def install_vault_client(name:, signature:, client:, generation:, **)
          vault_clients_mutex.synchronize do
            raise IOError, 'Vault clients cleared during construction' unless generation == (@vault_client_generation || 0)
            raise IOError, 'Crypt stopped during client construction' if Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping

            entry = @vault_clients[name]
            current_signature = vault_client_signature(config: name.nil? ? Legion::Settings[:crypt][:vault] : clusters[name])
            cached = cached_vault_client(entry: entry, signature: current_signature)
            return cached if cached
            return unless signature == current_signature

            (@retired_vault_clients ||= ObjectSpace::WeakMap.new)[entry[:client]] = true if entry
            @vault_clients[name] = { client: client, signature: signature }
            client
          end
        end

        def resolve_vault_address(vault_settings:, **)
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

        def vault_client_signature(config:, **)
          return unless config.is_a?(Hash)

          tls = Legion::Crypt::TLS.migrate_legacy(config[:tls] || {})
          verify = %w[none mutual].include?(tls[:verify].to_s) ? tls[:verify].to_s : 'peer'

          namespace =
            if config.key?(:namespace)
              config[:namespace]
            else
              Legion::Settings[:crypt][:vault][:vault_namespace]
            end
          {
            address: resolve_vault_address(vault_settings: config), namespace: namespace, token: config[:token],
            verify: verify, ca: tls[:ca], cert: tls[:cert], key: tls[:key],
            timeout: Legion::Settings[:crypt][:vault][:operation_timeout]
          }
        end

        def build_vault_client(signature, name:)
          building = Thread.current[:legion_vault_clients_building] ||= []
          build_key = [self, name]
          raise IOError, 'Circular Vault TLS material dependency' if building.include?(build_key)

          building << build_key
          begin
            tls = Legion::Crypt::TLS.resolve(signature.slice(:verify, :ca, :cert, :key))
            %i[ca cert key].each do |attribute|
              raise IOError, "Configured Vault TLS #{attribute} could not be resolved" if signature[attribute] && tls[attribute].nil?
            end
            options = signature.slice(:address, :namespace, :token, :timeout).merge(tls: tls)
            log.info "Building Vault client address=#{options[:address]} namespace=#{options[:namespace].inspect} tls_verify=#{tls[:verify]}"
            Legion::Crypt::Vault::Client.new(**options)
          ensure
            building.delete(build_key)
          end
        end

        def retire_vault_client(client:, deadline: nil, **)
          return unless client.respond_to?(:shutdown)

          Legion::Crypt::Vault::Operation.with_timeout(deadline: deadline) do
            client.shutdown
          end
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.vault_cluster.retire_vault_client')
        end
      end
    end
  end
end
