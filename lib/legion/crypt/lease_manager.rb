# frozen_string_literal: true

require 'legion/logging/helper'
require 'singleton'
require 'timeout'

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
        @state_mutex = Mutex.new
      end

      def start(definitions, vault_client: nil)
        @state_mutex.synchronize { @vault_client = vault_client }
        return if definitions.nil? || definitions.empty?

        register_at_exit_hook

        log.info "LeaseManager start requested definitions=#{definitions.size}"
        definitions.each do |name, opts|
          path = opts['path'] || opts[:path]
          next unless path

          if lease_valid?(name)
            log.debug("LeaseManager: reusing valid cached lease for '#{name}'")
            next
          end

          revoke_expired_lease(name)

          begin
            response = logical.read(path)
            unless response
              log.warn("LeaseManager: no data at '#{name}' (#{path}) — path may not exist or role not configured")
              next
            end

            log_lease_response(name, response)
            cache_lease(name, response)
            log.info("LeaseManager: fetched lease for '#{name}' from #{path}")
          rescue StandardError => e
            handle_exception(e, level: :warn, operation: 'crypt.lease_manager.start', lease_name: name, path: path)
            log.warn("LeaseManager: failed to fetch lease '#{name}' from #{path}: #{e.message}")
          end
        end
      end

      def fetched_count
        @state_mutex.synchronize { @active_leases.size }
      end

      def fetch(name, key)
        data = @state_mutex.synchronize do
          @lease_cache[name.to_sym] || @lease_cache[name.to_s]
        end
        return nil unless data

        data[key.to_sym] || data[key.to_s]
      end

      def lease_data(name)
        @state_mutex.synchronize { @lease_cache[name] }
      end

      attr_reader :active_leases

      def register_ref(name, key, path)
        @state_mutex.synchronize do
          @refs[name] ||= {}
          @refs[name][key] = path
        end
      end

      def push_to_settings(name)
        refs, data = @state_mutex.synchronize do
          [@refs[name]&.dup, @lease_cache[name]&.dup]
        end
        return if refs.nil? || refs.empty?
        return unless data

        refs.each do |key, path|
          value = data[key.to_sym] || data[key.to_s]
          write_setting(path, value)
        end

        log.info("Lease '#{name}' rotated — updated #{refs.size} settings reference(s)")
      end

      # Public Vault client accessors used by Crypt for bootstrap/swap operations.
      # Delegates to the configured vault_client or falls back to ::Vault.
      def vault_logical
        logical
      end

      def vault_sys
        sys
      end

      def register_dynamic_lease(name:, path:, response:, settings_refs:)
        register_at_exit_hook

        @state_mutex.synchronize do
          @lease_cache[name] = response.data || {}
          @active_leases[name] = {
            lease_id:       response.lease_id,
            lease_duration: response.lease_duration,
            expires_at:     Time.now + (response.lease_duration || 0),
            fetched_at:     Time.now,
            renewable:      response.renewable?,
            path:           path
          }
        end
        settings_refs.each do |ref|
          register_ref(name, ref[:key], ref[:path])
        end
        log.info("LeaseManager: registered dynamic lease '#{name}' (path: #{path})")
      end

      def reissue_lease(name)
        lease = @state_mutex.synchronize { @active_leases[name]&.dup }
        return unless lease && lease[:path]

        response = logical.read(lease[:path])
        return unless response&.data

        @state_mutex.synchronize do
          active_lease = @active_leases[name]
          next unless active_lease

          @lease_cache[name] = response.data
          active_lease.merge!(
            lease_id:       response.lease_id,
            lease_duration: response.lease_duration,
            expires_at:     Time.now + (response.lease_duration || 0),
            fetched_at:     Time.now,
            renewable:      response.renewable?
          )
        end
        push_to_settings(name)

        return unless name == :rabbitmq && defined?(Legion::Transport::Connection)

        Legion::Transport::Connection.force_reconnect
        log.info("LeaseManager: reissued lease '#{name}' and triggered transport reconnect")
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.reissue_lease', lease_name: name)
        log.warn("LeaseManager: failed to reissue lease '#{name}': #{e.message}")
      end

      def start_renewal_thread
        @state_mutex.synchronize do
          return if @renewal_thread&.alive?

          @running = true
          @renewal_thread = Thread.new { renewal_loop }
        end
        log.info 'LeaseManager renewal thread started'
      end

      def renewal_thread_alive?
        @state_mutex.synchronize { @renewal_thread&.alive? || false }
      end

      def shutdown
        log.info 'LeaseManager shutdown requested'
        stop_renewal_thread

        leases = @state_mutex.synchronize { @active_leases.dup }
        leases.each do |name, meta|
          lease_id = meta[:lease_id]
          next if lease_id.nil? || lease_id.empty?

          begin
            sys.revoke(lease_id)
            log.debug("LeaseManager: revoked lease '#{name}' (#{lease_id})")
          rescue StandardError => e
            handle_exception(e, level: :warn, operation: 'crypt.lease_manager.shutdown', lease_name: name)
            log.warn("LeaseManager: failed to revoke lease '#{name}' (#{lease_id}): #{e.message}")
          end
        end

        @state_mutex.synchronize do
          @lease_cache.clear
          @active_leases.clear
          @refs.clear
          @vault_client = nil
        end
        log.info 'LeaseManager shutdown complete'
      end

      def reset!
        @state_mutex.synchronize do
          @running = false
          @lease_cache.clear
          @active_leases.clear
          @refs.clear
          @vault_client = nil
          @renewal_thread = nil
        end
      end

      private

      def register_at_exit_hook
        return if @at_exit_registered

        at_exit do
          next if @state_mutex.synchronize { @active_leases.empty? }

          Timeout.timeout(10) { shutdown }
        rescue Timeout::Error
          warn '[LeaseManager] at_exit shutdown timed out after 10s'
        rescue StandardError # best effort on crash
          nil
        end
        @at_exit_registered = true
      end

      def cache_lease(name, response)
        @state_mutex.synchronize do
          @lease_cache[name] = response.data || {}
          @active_leases[name] = {
            lease_id:       response.lease_id,
            lease_duration: response.lease_duration,
            renewable:      response.renewable?,
            expires_at:     Time.now + (response.lease_duration || 0),
            fetched_at:     Time.now
          }
        end
      end

      def log_lease_response(name, response)
        data_keys = response.data&.keys&.map(&:to_s) || []
        log.debug("LeaseManager[#{name}]: lease_id=#{response.lease_id}, " \
                  "lease_duration=#{response.lease_duration}s, " \
                  "renewable=#{response.renewable?}, " \
                  "data_keys=#{data_keys.inspect}")
        return unless response.data&.key?(:username)

        log.debug("LeaseManager[#{name}]: username=#{response.data[:username]}, " \
                  "password_length=#{response.data[:password]&.length || 0}, " \
                  "vhost=#{response.data[:vhost] || 'N/A'}, " \
                  "tags=#{response.data[:tags] || 'N/A'}")
      end

      def logical
        client = @state_mutex.synchronize { @vault_client }
        client ? client.logical : ::Vault.logical
      end

      def sys
        client = @state_mutex.synchronize { @vault_client }
        client ? client.sys : ::Vault.sys
      end

      def stop_renewal_thread
        thread = @state_mutex.synchronize do
          @running = false
          @renewal_thread
        end
        return unless thread

        begin
          thread.wakeup if thread.alive?
        rescue ThreadError => e
          handle_exception(e, level: :debug, operation: 'crypt.lease_manager.stop_renewal_thread')
        end
        thread.join(2)
        if thread.alive?
          log.warn 'LeaseManager renewal thread did not stop within timeout'
        else
          @state_mutex.synchronize { @renewal_thread = nil }
          log.debug 'LeaseManager renewal thread stopped'
        end
      end

      def renewal_loop
        while running?
          interruptible_sleep(RENEWAL_CHECK_INTERVAL)
          renew_approaching_leases if running?
        end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.lease_manager.renewal_loop')
        log.error("LeaseManager: renewal loop error: #{e.message}")
        retry if running?
      end

      def renew_approaching_leases
        leases = @state_mutex.synchronize { @active_leases.keys }
        leases.each do |name|
          lease = @state_mutex.synchronize { @active_leases[name]&.dup }
          next unless lease
          next unless approaching_expiry?(lease)

          if lease[:renewable]
            renew_lease(name, lease)
          elsif lease[:path]
            log.info("LeaseManager: lease '#{name}' is non-renewable and approaching expiry — re-issuing")
            reissue_lease(name)
          end
        end
      end

      def renew_lease(name, lease)
        response = sys.renew(lease[:lease_id])
        @state_mutex.synchronize do
          current_lease = @active_leases[name]
          next unless current_lease

          current_lease[:lease_duration] = response.lease_duration if response.respond_to?(:lease_duration)
          current_lease[:renewable] = response.renewable? if response.respond_to?(:renewable?)
          current_lease[:expires_at] = Time.now + (response.lease_duration || 0)
        end
        log.info("LeaseManager: renewed lease '#{name}'")

        cached_data = @state_mutex.synchronize { @lease_cache[name] }
        if response.data && response.data != cached_data
          @state_mutex.synchronize { @lease_cache[name] = response.data }
          push_to_settings(name)
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.renew_lease', lease_name: name)
        log.warn("LeaseManager: failed to renew lease '#{name}': #{e.message}")
        reissue_lease(name) if lease[:path]
      end

      def lease_valid?(name)
        meta = @state_mutex.synchronize { @active_leases[name]&.dup }
        return false unless meta

        expires_at = meta[:expires_at]
        return false unless expires_at

        expires_at > Time.now
      end

      def revoke_expired_lease(name)
        meta = @state_mutex.synchronize { @active_leases[name]&.dup }
        return unless meta

        lease_id = meta[:lease_id]
        return if lease_id.nil? || lease_id.empty?

        begin
          sys.revoke(lease_id)
          log.debug("LeaseManager: revoked expired lease '#{name}' (#{lease_id}) before re-fetch")
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.lease_manager.revoke_expired_lease', lease_name: name)
          log.warn("LeaseManager: failed to revoke expired lease '#{name}' (#{lease_id}): #{e.message}")
        ensure
          @state_mutex.synchronize do
            @active_leases.delete(name)
            @lease_cache.delete(name)
          end
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

      def running?
        @state_mutex.synchronize { @running }
      end

      def interruptible_sleep(seconds)
        deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + seconds
        loop do
          remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
          break if remaining <= 0 || !running?

          sleep([remaining, 1.0].min)
        end
      end
    end
  end
end
