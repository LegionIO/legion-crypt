# frozen_string_literal: true

require 'legion/logging/helper'
require 'singleton'

module Legion
  module Crypt
    class LeaseManager
      include Singleton
      include Legion::Logging::Helper

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

        log.info "LeaseManager start requested definitions=#{definitions.size}"
        definitions.each do |name, opts|
          path = opts['path'] || opts[:path]
          next unless path

          if lease_valid?(name)
            log_debug("LeaseManager: reusing valid cached lease for '#{name}'")
            next
          end

          revoke_expired_lease(name)

          begin
            response = logical.read(path)
            unless response
              log.warn("LeaseManager: no data at '#{name}' (#{path}) — path may not exist or role not configured")
              next
            end

            @lease_cache[name] = response.data || {}
            @active_leases[name] = {
              lease_id:       response.lease_id,
              lease_duration: response.lease_duration,
              renewable:      response.renewable?,
              expires_at:     Time.now + (response.lease_duration || 0),
              fetched_at:     Time.now
            }
            log.info("LeaseManager: fetched lease for '#{name}' from #{path}")
          rescue StandardError => e
            handle_exception(e, level: :warn, operation: 'crypt.lease_manager.start', lease_name: name, path: path)
            log.warn("LeaseManager: failed to fetch lease '#{name}' from #{path}: #{e.message}")
          end
        end
      end

      def fetched_count
        @active_leases.size
      end

      def fetch(name, key)
        data = @lease_cache[name.to_sym] || @lease_cache[name.to_s]
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

        log.info("Lease '#{name}' rotated — updated #{refs.size} settings reference(s)")
      end

      def start_renewal_thread
        return if renewal_thread_alive?

        @running = true
        @renewal_thread = Thread.new { renewal_loop }
        log.info 'LeaseManager renewal thread started'
      end

      def renewal_thread_alive?
        @renewal_thread&.alive? || false
      end

      def shutdown
        log.info 'LeaseManager shutdown requested'
        stop_renewal_thread

        @active_leases.each do |name, meta|
          lease_id = meta[:lease_id]
          next if lease_id.nil? || lease_id.empty?

          begin
            sys.revoke(lease_id)
            log_debug("LeaseManager: revoked lease '#{name}' (#{lease_id})")
          rescue StandardError => e
            handle_exception(e, level: :warn, operation: 'crypt.lease_manager.shutdown', lease_name: name)
            log.warn("LeaseManager: failed to revoke lease '#{name}' (#{lease_id}): #{e.message}")
          end
        end

        @lease_cache.clear
        @active_leases.clear
        @refs.clear
        @vault_client = nil
        log.info 'LeaseManager shutdown complete'
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
        log.debug 'LeaseManager renewal thread stopped'
      end

      def renewal_loop
        while @running
          sleep(RENEWAL_CHECK_INTERVAL)
          renew_approaching_leases if @running
        end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.lease_manager.renewal_loop')
        log.error("LeaseManager: renewal loop error: #{e.message}")
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
        log.info("LeaseManager: renewed lease '#{name}'")

        if response.data && response.data != @lease_cache[name]
          @lease_cache[name] = response.data
          push_to_settings(name)
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.renew_lease', lease_name: name)
        log.warn("LeaseManager: failed to renew lease '#{name}': #{e.message}")
      end

      def lease_valid?(name)
        meta = @active_leases[name]
        return false unless meta

        expires_at = meta[:expires_at]
        return false unless expires_at

        expires_at > Time.now
      end

      def revoke_expired_lease(name)
        meta = @active_leases[name]
        return unless meta

        lease_id = meta[:lease_id]
        return if lease_id.nil? || lease_id.empty?

        begin
          sys.revoke(lease_id)
          log_debug("LeaseManager: revoked expired lease '#{name}' (#{lease_id}) before re-fetch")
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.lease_manager.revoke_expired_lease', lease_name: name)
          log.warn("LeaseManager: failed to revoke expired lease '#{name}' (#{lease_id}): #{e.message}")
        ensure
          @active_leases.delete(name)
          @lease_cache.delete(name)
        end
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
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.write_setting', path: path.join('.'))
        log.warn("LeaseManager: failed to write setting at #{path.join('.')}: #{e.message}")
      end

      def log_debug(message)
        log.debug(message)
      end
    end
  end
end
