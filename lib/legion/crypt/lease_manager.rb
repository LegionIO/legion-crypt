# frozen_string_literal: true

require 'singleton'

module Legion
  module Crypt
    class LeaseManager
      include Singleton

      RENEWAL_CHECK_INTERVAL = 5

      def initialize
        @lease_cache = {}
        @active_leases = {}
        @refs = {}
        @running = false
        @renewal_thread = nil
      end

      def start(definitions, vault_client: nil)
        @vault_client = vault_client
        return if definitions.nil? || definitions.empty?

        definitions.each do |name, opts|
          path = opts['path'] || opts[:path]
          next unless path

          begin
            response = logical.read(path)
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

      def start_renewal_thread
        return if renewal_thread_alive?

        @running = true
        @renewal_thread = Thread.new { renewal_loop }
      end

      def renewal_thread_alive?
        @renewal_thread&.alive? || false
      end

      def shutdown
        stop_renewal_thread

        @active_leases.each do |name, meta|
          lease_id = meta[:lease_id]
          next if lease_id.nil? || lease_id.empty?

          begin
            sys.revoke(lease_id)
            log_debug("LeaseManager: revoked lease '#{name}' (#{lease_id})")
          rescue StandardError => e
            log_warn("LeaseManager: failed to revoke lease '#{name}' (#{lease_id}): #{e.message}")
          end
        end

        @lease_cache.clear
        @active_leases.clear
        @refs.clear
        @vault_client = nil
      end

      def reset!
        @running = false
        @lease_cache.clear
        @active_leases.clear
        @refs.clear
        @vault_client = nil
      end

      private

      def logical
        @vault_client ? @vault_client.logical : ::Vault.logical
      end

      def sys
        @vault_client ? @vault_client.sys : ::Vault.sys
      end

      def stop_renewal_thread
        @running = false
        if @renewal_thread&.alive?
          @renewal_thread.kill
          @renewal_thread.join(2)
        end
        @renewal_thread = nil
      end

      def renewal_loop
        while @running
          sleep(RENEWAL_CHECK_INTERVAL)
          renew_approaching_leases if @running
        end
      rescue StandardError => e
        log_warn("LeaseManager: renewal loop error: #{e.message}")
        retry if @running
      end

      def renew_approaching_leases
        @active_leases.each do |name, lease|
          next unless lease[:renewable]
          next unless approaching_expiry?(lease)

          renew_lease(name, lease)
        end
      end

      def renew_lease(name, lease)
        response = sys.renew(lease[:lease_id])
        lease[:expires_at] = Time.now + (response.lease_duration || 0)

        if response.data && response.data != @lease_cache[name]
          @lease_cache[name] = response.data
          push_to_settings(name)
        end
      rescue StandardError => e
        log_warn("LeaseManager: failed to renew lease '#{name}': #{e.message}")
      end

      def approaching_expiry?(lease)
        expires_at = lease[:expires_at]
        lease_duration = lease[:lease_duration]

        return true if expires_at.nil? || lease_duration.nil?

        remaining = expires_at - Time.now
        remaining < (lease_duration * 0.5)
      end

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
