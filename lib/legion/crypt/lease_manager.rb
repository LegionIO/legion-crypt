# frozen_string_literal: true

require 'singleton'

module Legion
  module Crypt
    class LeaseManager
      include Singleton

      def initialize
        @lease_cache = {}
        @active_leases = {}
        @refs = {}
      end

      def start(definitions)
        return if definitions.nil? || definitions.empty?

        definitions.each do |name, opts|
          path = opts['path'] || opts[:path]
          next unless path

          begin
            response = ::Vault.logical.read(path)
            next unless response

            @lease_cache[name] = response.data || {}
            @active_leases[name] = {
              lease_id:       response.lease_id,
              lease_duration: response.lease_duration,
              renewable:      response.renewable,
              expires_at:     Time.now + (response.lease_duration || 0),
              fetched_at:     Time.now
            }
            log_debug("LeaseManager: fetched lease for '#{name}' from #{path}")
          rescue StandardError => e
            log_warn("LeaseManager: failed to fetch lease '#{name}' from #{path}: #{e.message}")
          end
        end
      end

      def fetch(name, key)
        data = @lease_cache[name]
        return nil unless data

        data[key.to_sym] || data[key.to_s]
      end

      def lease_data(name)
        @lease_cache[name]
      end

      attr_reader :active_leases

      def register_ref(name, key, path)
        @refs[name] ||= {}
        @refs[name][key] = path
      end

      def push_to_settings(name)
        refs = @refs[name]
        return if refs.nil? || refs.empty?

        data = @lease_cache[name]
        return unless data

        refs.each do |key, path|
          value = data[key.to_sym] || data[key.to_s]
          write_setting(path, value)
        end

        log_debug("Lease '#{name}' rotated — updated #{refs.size} settings reference(s)")
      end

      def shutdown
        @active_leases.each do |name, meta|
          lease_id = meta[:lease_id]
          next if lease_id.nil? || lease_id.empty?

          begin
            ::Vault.sys.revoke(lease_id)
            log_debug("LeaseManager: revoked lease '#{name}' (#{lease_id})")
          rescue StandardError => e
            log_warn("LeaseManager: failed to revoke lease '#{name}' (#{lease_id}): #{e.message}")
          end
        end

        @lease_cache.clear
        @active_leases.clear
        @refs.clear
      end

      def reset!
        @lease_cache.clear
        @active_leases.clear
        @refs.clear
      end

      private

      def write_setting(path, value)
        return if path.nil? || path.empty?

        target = path[1..-2].reduce(Legion::Settings[path[0]]) do |node, segment|
          break nil unless node.is_a?(Hash)

          node[segment]
        end
        target[path.last] = value if target.is_a?(Hash)
      rescue StandardError => e
        log_warn("LeaseManager: failed to write setting at #{path.join('.')}: #{e.message}")
      end

      def log_debug(message)
        if defined?(Legion::Logging)
          Legion::Logging.debug(message)
        else
          $stdout.puts("[DEBUG] #{message}")
        end
      end

      def log_warn(message)
        if defined?(Legion::Logging)
          Legion::Logging.warn(message)
        else
          warn("[WARN] #{message}")
        end
      end
    end
  end
end
