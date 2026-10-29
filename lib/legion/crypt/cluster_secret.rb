# frozen_string_literal: true

require 'securerandom'
require 'digest'
require 'timeout'
require 'legion/logging/helper'

module Legion
  module Crypt
    module ClusterSecret
      class InitializationError < StandardError; end

      include Legion::Logging::Helper

      def find_cluster_secret
        secret_length
        cluster_secret_timeout
        raise InitializationError, 'Cluster secret initialization cancelled during shutdown' if Legion::Settings[:client]&.dig(:shutting_down)

        %i[from_settings from_vault from_transport].each do |method|
          result = send(method)
          next if result.nil?

          unless validate_hex(result)
            raise InitializationError, 'Configured cluster secret is not valid hexadecimal key material' if method == :from_settings

            log.warn("Legion::Crypt.#{method} gave a value but it isn't a valid hex")
            next
          end

          set_cluster_secret(result, method != :from_vault)
          return result
        end
        return unless only_member? == true

        key = generate_secure_random
        set_cluster_secret(key)
        log.info 'Cluster secret generated locally because this node is the only member'
        key
      end

      def from_vault
        return nil unless Legion::Crypt.respond_to?(:get) && Legion::Crypt.respond_to?(:exist?)
        return nil unless Legion::Settings[:crypt][:vault][:read_cluster_secret]
        return nil unless Legion::Settings[:crypt][:vault][:connected]
        return nil unless Legion::Crypt.exist?(cluster_secret_vault_path)

        data = Legion::Crypt.get(cluster_secret_vault_path)
        return nil unless data.is_a?(Hash)

        data[:cluster_secret] || data['cluster_secret']
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.cluster_secret.from_vault')
        nil
      end

      def from_settings
        Legion::Settings[:crypt][:cluster_secret]
      end
      alias cluster_secret from_settings

      def from_transport
        return nil unless Legion::Settings[:transport]&.dig(:connected)
        return nil if defined?(Legion::Transport::TYPE) && Legion::Transport::TYPE == 'local'

        require 'legion/transport/messages/request_cluster_secret'
        log.info 'Requesting cluster secret via public key'
        log.warn 'cluster_secret already set but we are requesting a new value' unless from_settings.nil?
        start = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
        deadline = start + cluster_secret_timeout
        Legion::Transport::Messages::RequestClusterSecret.new.publish
        sleep_time = 0.001
        while from_settings.nil?
          raise InitializationError, 'Cluster secret initialization cancelled during shutdown' if Legion::Settings[:client]&.dig(:shutting_down)

          remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
          break unless remaining.positive?

          sleep([sleep_time, remaining].min)
          sleep_time = [sleep_time * 2, 0.5].min
        end

        unless from_settings.nil?
          elapsed = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) - start
          log.info "Received cluster secret in #{(elapsed * 1000.0).round}ms"
          return from_settings
        end

        log.error 'Cluster secret is still unknown!'
        nil
      rescue InitializationError
        raise
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cluster_secret.from_transport')
        nil
      end

      def force_cluster_secret
        Legion::Settings[:crypt].fetch(:force_cluster_secret, false)
      end

      def settings_push_vault
        vault_settings = Legion::Settings[:crypt][:vault]
        return vault_settings[:push_cluster_secret] unless vault_settings[:push_cluster_secret].nil?

        vault_settings.fetch(:push_cs_to_vault, false)
      end

      def only_member?
        return true if defined?(Legion::Transport::TYPE) && Legion::Transport::TYPE == 'local'

        transport = Legion::Settings[:transport]
        return Legion::Transport::Queue.new('node.crypt', passive: true).consumer_count.zero? if transport&.dig(:connected)

        return true unless defined?(Legion::Transport)
        return true if transport&.dig(:enabled) == false
        return true if defined?(Legion::Mode) ? Legion::Mode.lite? : ENV['LEGION_MODE'] == 'lite'

        nil
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.cluster_secret.only_member?')
        nil
      end

      def set_cluster_secret(value, push_to_vault = true) # rubocop:disable Style/OptionalBooleanParameter
        raise TypeError unless validate_hex(value)

        Legion::Settings[:crypt][:cluster_secret] = value.dup.freeze
        @cluster_secret_cache = nil
        Legion::Settings[:crypt][:cs_encrypt_ready] = true
        push_cs_to_vault if push_to_vault && settings_push_vault
        log.info "Cluster secret loaded into settings push_to_vault=#{push_to_vault}"
      end

      def push_cs_to_vault
        return false unless Legion::Settings[:crypt][:vault][:connected] && Legion::Settings[:crypt][:cluster_secret]

        log.info 'Pushing Cluster Secret to Vault'
        Legion::Crypt.write(cluster_secret_vault_path, cluster_secret: Legion::Settings[:crypt][:cluster_secret])
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.cluster_secret.push_cs_to_vault')
        false
      end

      def cluster_secret_timeout
        timeout = Legion::Settings[:crypt].fetch(:cluster_secret_timeout, 5)
        unless timeout.is_a?(Numeric) && timeout.finite? && timeout.positive?
          raise InitializationError, 'cluster_secret_timeout must be a finite positive number'
        end

        timeout
      end

      def secret_length
        length = Legion::Settings[:crypt][:cluster_length] || Legion::Settings[:crypt][:cluster_lenth] || 32
        raise InitializationError, 'cluster_length must be a positive integer' unless length.is_a?(Integer) && length.positive?

        length
      end

      def generate_secure_random(length = secret_length)
        SecureRandom.hex(length)
      end

      def cs
        secret_length
        raise InitializationError, 'Cluster secret initialization cancelled during shutdown' if Legion::Settings[:client]&.dig(:shutting_down)

        source = from_settings || Timeout.timeout(cluster_secret_timeout) { find_cluster_secret }
        raise InitializationError, 'No validated cluster secret is available' unless validate_hex(source)

        Legion::Settings[:crypt][:cs_encrypt_ready] = true
        cached = @cluster_secret_cache
        return cached[:key] if cached && cached[:secret] == source

        source = source.dup.freeze
        key = Digest::SHA256.digest(source)
        @cluster_secret_cache = { secret: source, key: key }.freeze
        key
      rescue StandardError => e
        Legion::Settings[:crypt][:cs_encrypt_ready] = false
        handle_exception(e, level: :error, operation: 'crypt.cluster_secret.cs')
        raise if e.is_a?(InitializationError)

        raise InitializationError, 'Cluster secret initialization failed'
      end

      def validate_hex(value, length = secret_length)
        return false unless value.is_a?(String)
        return false if value.empty?
        return false unless value.match?(/\A\h+\z/)

        length.is_a?(Integer) && length.positive? && value.length == length * 2
      end

      def cluster_secret_vault_path
        'crypt'
      end
    end
  end
end
