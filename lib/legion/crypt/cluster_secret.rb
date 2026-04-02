# frozen_string_literal: true

require 'securerandom'
require 'legion/logging/helper'

module Legion
  module Crypt
    module ClusterSecret
      include Legion::Logging::Helper

      def find_cluster_secret
        %i[from_settings from_vault from_transport generate_secure_random].each do |method|
          result = send(method)
          next if result.nil?

          unless validate_hex(result)
            log.warn("Legion::Crypt.#{method} gave a value but it isn't a valid hex")
            next
          end

          set_cluster_secret(result, method != :from_vault)
          return result
        end
        return unless only_member?

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
        return nil unless Legion::Settings[:transport][:connected]

        require 'legion/transport/messages/request_cluster_secret'
        log.info 'Requesting cluster secret via public key'
        log.warn 'cluster_secret already set but we are requesting a new value' unless from_settings.nil?
        start = Time.now
        Legion::Transport::Messages::RequestClusterSecret.new.publish
        sleep_time = 0.001
        until !Legion::Settings[:crypt][:cluster_secret].nil? || (Time.now - start) > cluster_secret_timeout
          sleep(sleep_time)
          sleep_time *= 2 unless sleep_time > 0.5
        end

        unless from_settings.nil?
          log.info "Received cluster secret in #{((Time.new - start) * 1000.0).round}ms"
          return from_settings
        end

        log.error 'Cluster secret is still unknown!'
        nil
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
        Legion::Transport::Queue.new('node.crypt', passive: true).consumer_count.zero?
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.cluster_secret.only_member?')
        nil
      end

      def set_cluster_secret(value, push_to_vault = true) # rubocop:disable Style/OptionalBooleanParameter
        raise TypeError unless validate_hex(value)

        Legion::Settings[:crypt][:cluster_secret] = value
        @cs = nil
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
        Legion::Settings[:crypt][:cluster_secret_timeout] || 5
      end

      def secret_length
        Legion::Settings[:crypt][:cluster_length] || Legion::Settings[:crypt][:cluster_lenth] || 32
      end

      def generate_secure_random(length = secret_length)
        SecureRandom.hex(length)
      end

      def cs
        @cs ||= Digest::SHA256.digest(find_cluster_secret)
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cluster_secret.cs')
        nil
      end

      def validate_hex(value, length = secret_length)
        return false unless value.is_a?(String)
        return false if value.empty?
        return false unless value.match?(/\A\h+\z/)

        expected_length = length.to_i * 2
        return true if expected_length.zero?

        value.length == expected_length
      end

      def cluster_secret_vault_path
        'crypt'
      end
    end
  end
end
