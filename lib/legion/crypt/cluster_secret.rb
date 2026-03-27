# frozen_string_literal: true

require 'securerandom'

module Legion
  module Crypt
    module ClusterSecret
      def find_cluster_secret
        %i[from_settings from_vault from_transport generate_secure_random].each do |method|
          result = send(method)
          next if result.nil?

          unless validate_hex(result)
            Legion::Logging.warn("Legion::Crypt.#{method} gave a value but it isn't a valid hex")
            next
          end

          set_cluster_secret(result, method != :from_vault)
          return result
        end
        return unless only_member?

        key = generate_secure_random
        set_cluster_secret(key)
        key
      end

      def from_vault
        return nil unless method_defined? :get
        return nil unless Legion::Settings[:crypt][:vault][:read_cluster_secret]
        return nil unless Legion::Settings[:crypt][:vault][:connected]
        return nil unless Legion::Crypt.exist?('crypt')

        get('crypt')[:cluster_secret]
      rescue StandardError => e
        Legion::Logging.warn("Legion::Crypt::ClusterSecret#from_vault failed: #{e.message}") if defined?(Legion::Logging)
        nil
      end

      def from_settings
        Legion::Settings[:crypt][:cluster_secret]
      end
      alias cluster_secret from_settings

      def from_transport
        return nil unless Legion::Settings[:transport][:connected]

        require 'legion/transport/messages/request_cluster_secret'
        Legion::Logging.info 'Requesting cluster secret via public key'
        Legion::Logging.warn 'cluster_secret already set but we are requesting a new value' unless from_settings.nil?
        start = Time.now
        Legion::Transport::Messages::RequestClusterSecret.new.publish
        sleep_time = 0.001
        until !Legion::Settings[:crypt][:cluster_secret].nil? || (Time.now - start) > cluster_secret_timeout
          sleep(sleep_time)
          sleep_time *= 2 unless sleep_time > 0.5
        end

        unless from_settings.nil?
          Legion::Logging.info "Received cluster secret in #{((Time.new - start) * 1000.0).round}ms"
          return from_settings
        end

        Legion::Logging.error 'Cluster secret is still unknown!'
        nil
      rescue StandardError => e
        Legion::Logging.log_exception(e, lex: 'crypt', component_type: :helper)
        nil
      end

      def force_cluster_secret
        Legion::Settings[:crypt][:force_cluster_secret] || true
      end

      def settings_push_vault
        Legion::Settings[:crypt][:vault][:push_cs_to_vault] || true
      end

      def only_member?
        Legion::Transport::Queue.new('node.crypt', passive: true).consumer_count.zero?
      rescue StandardError => e
        Legion::Logging.warn("Legion::Crypt::ClusterSecret#only_member? failed: #{e.message}") if defined?(Legion::Logging)
        nil
      end

      def set_cluster_secret(value, push_to_vault = true) # rubocop:disable Style/OptionalBooleanParameter
        raise TypeError unless value.to_i(32).to_s(32).rjust(value.length, '0') == value.downcase

        Legion::Settings[:crypt][:cs_encrypt_ready] = true
        push_cs_to_vault if push_to_vault && settings_push_vault

        Legion::Settings[:crypt][:cluster_secret] = value
      end

      def push_cs_to_vault
        return false unless Legion::Settings[:crypt][:vault][:connected] && Legion::Settings[:crypt][:cluster_secret]

        Legion::Logging.info 'Pushing Cluster Secret to Vault'
        Legion::Crypt.write('cluster', secret: Legion::Settings[:crypt][:cluster_secret])
      end

      def cluster_secret_timeout
        Legion::Settings[:crypt][:cluster_secret_timeout] || 5
      end

      def secret_length
        Legion::Settings[:crypt][:cluster_lenth] || 32
      end

      def generate_secure_random(length = secret_length)
        SecureRandom.hex(length)
      end

      def cs
        @cs ||= Digest::SHA256.digest(find_cluster_secret)
      rescue StandardError => e
        Legion::Logging.log_exception(e, lex: 'crypt', component_type: :helper) if defined?(Legion::Logging) && Legion::Logging.respond_to?(:log_exception)
        nil
      end

      def validate_hex(value, length = secret_length)
        return false unless value.is_a?(String)
        return false if value.empty?

        value.to_i(length).to_s(length).rjust(value.length, '0') == value.downcase
      end
    end
  end
end
