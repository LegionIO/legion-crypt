# frozen_string_literal: true

require 'legion/logging/helper'
require 'singleton'
require 'timeout'
require 'legion/crypt/vault_operation'

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
        @generation = 0
        @stopped = false
        @renewal_generation = nil
      end

      def start(definitions, vault_client: nil)
        generation = @state_mutex.synchronize do
          return if Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping

          @stopped = false
          @vault_client = vault_client
          @generation
        end
        return if definitions.nil? || definitions.empty?

        register_at_exit_hook
        definitions.each do |name, opts|
          break unless lifecycle_current?(generation)

          path = opts['path'] || opts[:path]
          next unless path
          next if lease_valid?(name)

          Legion::Crypt::VaultOperation.with_timeout do
            revoke_expired_lease(name, generation: generation)
            response = (vault_client ? vault_client.logical : ::Vault.logical).read(path)
            unless response
              log.warn("LeaseManager: no data at '#{name}' (#{path})")
              next
            end
            log_lease_response(name, response)
            cache_lease(name, response, path: path, generation: generation)
          end
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.lease_manager.start', lease_name: name, path: path)
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

      def register_ref(name, key, path, generation: @generation)
        with_current_state(generation: generation) do
          @refs[name] ||= {}
          @refs[name][key] = path
        end
      end

      def push_to_settings(name, generation: @generation, active: nil)
        count = with_current_state(generation: generation, active: active) do
          refs = @refs[name] || @refs[name.to_s] || @refs[name.to_sym]
          data = @lease_cache[name] || @lease_cache[name.to_s] || @lease_cache[name.to_sym]
          return if refs.nil? || refs.empty? || data.nil?

          refs.each do |key, path|
            write_setting(path, data[key.to_sym] || data[key.to_s])
          end
          refs.size
        end
        return unless count

        log.info("Lease '#{name}' rotated — updated #{count} settings reference(s)")
      end

      # Public Vault client accessors used by Crypt for bootstrap/swap operations.
      # Delegates to the configured vault_client or falls back to ::Vault.
      def vault_logical
        logical
      end

      def vault_sys
        sys
      end

      def reissue_all(active: nil)
        lease_names, generation = @state_mutex.synchronize { [@active_leases.keys, @generation] }
        lease_names.each do |name|
          break unless lifecycle_current?(generation, active: active)

          reissue_lease(name, generation: generation, active: active)
        end
      end

      def register_dynamic_lease(name:, path:, response:, settings_refs:)
        generation = @state_mutex.synchronize { @generation }
        register_at_exit_hook

        with_current_state(generation: generation) do
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
          register_ref(name, ref[:key], ref[:path], generation: generation)
        end
        log.info("LeaseManager: registered dynamic lease '#{name}' (path: #{path})")
      end

      def reissue_lease(name, generation: @generation, active: nil, deadline: nil)
        lease, client = @state_mutex.synchronize { [@active_leases[name]&.dup, @vault_client] }
        return unless lease && lease[:path] && lifecycle_current?(generation, active: active)

        Legion::Crypt::VaultOperation.with_timeout(deadline: deadline) do
          response = (client ? client.logical : ::Vault.logical).read(lease[:path])
          return unless response&.data

          updated = with_current_state(generation: generation, active: active) do
            current = @active_leases[name]
            next false unless current && current[:lease_id] == lease[:lease_id]

            @lease_cache[name] = response.data
            current.merge!(
              lease_id: response.lease_id, lease_duration: response.lease_duration,
              expires_at: Time.now + (response.lease_duration || 0), fetched_at: Time.now, renewable: response.renewable?
            )
            true
          end
          return unless updated

          push_to_settings(name, generation: generation, active: active)
          trigger_reconnect(name, generation: generation, active: active)
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.reissue_lease', lease_name: name)
      end

      def start_renewal_thread
        previous = @state_mutex.synchronize { @renewal_thread if @renewal_generation != @generation }
        Legion::Crypt::VaultOperation.with_timeout { previous.join } if previous&.alive?
        @state_mutex.synchronize do
          return if @renewal_thread&.alive? || @stopped
          return if Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping

          @running = true
          generation = @generation
          @renewal_generation = generation
          @renewal_thread = Thread.new { renewal_loop(generation: generation) }
        end
        log.info 'LeaseManager renewal thread started'
      end

      def renewal_thread_alive?
        @state_mutex.synchronize { @renewal_thread&.alive? || false }
      end

      def request_stop
        thread = @state_mutex.synchronize do
          @stopped = true
          @running = false
          @generation += 1
          @renewal_thread
        end
        thread.wakeup if thread&.alive?
        thread
      rescue ThreadError => e
        handle_exception(e, level: :debug, operation: 'crypt.lease_manager.request_stop')
        thread
      end

      def shutdown(deadline: nil)
        deadline ||= ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + Legion::Crypt::VaultOperation::SHUTDOWN_TIMEOUT
        request_stop
        leases, client = @state_mutex.synchronize do
          snapshot = @active_leases
          @active_leases = {}
          @lease_cache.clear
          @refs.clear
          owner = @vault_client
          @vault_client = nil
          [snapshot, owner]
        end
        stop_renewal_thread(deadline: deadline)
        leases.each do |name, meta|
          lease_id = meta[:lease_id]
          next if lease_id.nil? || lease_id.empty?

          Legion::Crypt::VaultOperation.with_timeout(deadline: deadline) do
            (client ? client.sys : ::Vault.sys).revoke(lease_id)
          end
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.lease_manager.shutdown', lease_name: name)
        end
        log.info 'LeaseManager shutdown complete'
      end

      def reset!
        stop_renewal_thread
        @state_mutex.synchronize do
          @lease_cache.clear
          @active_leases.clear
          @refs.clear
          @vault_client = nil
          @stopped = false
        end
      end

      private

      def register_at_exit_hook
        return if @at_exit_registered

        at_exit do
          next if @state_mutex.synchronize { @active_leases.empty? }

          Timeout.timeout(10) { shutdown }
        rescue Timeout::Error => e
          log.warn("[LeaseManager] at_exit shutdown timed out after 10s: #{e.message}")
        rescue StandardError => e # best effort on crash
          log.warn("[LeaseManager] at_exit shutdown failed: #{e.class}: #{e.message}")
        end
        @at_exit_registered = true
      end

      def cache_lease(name, response, path: nil, generation: @generation)
        with_current_state(generation: generation) do
          @lease_cache[name] = response.data || {}
          @active_leases[name] = {
            lease_id:       response.lease_id,
            lease_duration: response.lease_duration,
            renewable:      response.renewable?,
            expires_at:     Time.now + (response.lease_duration || 0),
            fetched_at:     Time.now,
            path:           path
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

      def stop_renewal_thread(deadline: nil)
        thread = request_stop
        return unless thread

        Legion::Crypt::VaultOperation.with_timeout(deadline: deadline) { thread.join }
        @state_mutex.synchronize { @renewal_thread = nil if @renewal_thread.equal?(thread) }
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.stop_renewal_thread')
      end

      def renewal_loop(generation:)
        log.info 'LeaseManager: renewal loop started'
        while running?(generation: generation)
          interruptible_sleep(RENEWAL_CHECK_INTERVAL, generation: generation)
          renew_approaching_leases(generation: generation) if running?(generation: generation)
        end
        log.info 'LeaseManager: renewal loop exiting'
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.lease_manager.renewal_loop')
        log.error("LeaseManager: renewal loop error: #{e.message} — restarting")
        retry if running?(generation: generation)
      end

      def renew_approaching_leases(generation: @generation)
        leases = @state_mutex.synchronize { @active_leases.keys }
        leases.each do |name|
          break unless lifecycle_current?(generation)

          lease = @state_mutex.synchronize { @active_leases[name]&.dup }
          next unless lease
          next unless approaching_expiry?(lease)

          remaining = lease[:expires_at] ? (lease[:expires_at] - Time.now).round(1) : 'unknown'
          log.debug("LeaseManager: lease '#{name}' approaching expiry " \
                    "(remaining=#{remaining}s renewable=#{lease[:renewable]} has_path=#{!lease[:path].nil?})")

          if lease[:renewable]
            renew_lease(name, lease, generation: generation)
          elsif lease[:path]
            log.info("LeaseManager: lease '#{name}' is non-renewable — re-issuing from #{lease[:path]}")
            reissue_lease(name, generation: generation)
          else
            log.warn("LeaseManager: lease '#{name}' is non-renewable and has no path for reissue — " \
                     "will expire at #{lease[:expires_at]}")
          end
        end
      end

      def renew_lease(name, lease, generation: @generation)
        return unless lifecycle_current?(generation)

        operation_deadline = nil
        client = @state_mutex.synchronize { @vault_client }
        Legion::Crypt::VaultOperation.with_timeout do |deadline|
          operation_deadline = deadline
          lease_id = lease[:lease_id].to_s
          if lease_id.empty?
            reissue_lease(name, generation: generation, deadline: deadline) if lease[:path]
            next
          end

          response = (client ? client.sys : ::Vault.sys).renew(lease_id)
          new_ttl = response.respond_to?(:lease_duration) ? response.lease_duration : nil
          updated = with_current_state(generation: generation) do
            current = @active_leases[name]
            next false unless current && current[:lease_id] == lease_id

            if new_ttl
              current[:lease_duration] = new_ttl
              current[:expires_at] = Time.now + new_ttl
            end
            current[:renewable] = response.renewable? if response.respond_to?(:renewable?)
            @lease_cache[name] = response.data if response.data
            true
          end
          push_to_settings(name, generation: generation) if updated
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.renew_lease', lease_name: name)
        reissue_lease(name, generation: generation, deadline: operation_deadline) if operation_deadline && !e.is_a?(Timeout::Error)
      end

      def lease_valid?(name)
        meta = @state_mutex.synchronize { @active_leases[name]&.dup }
        return false unless meta

        expires_at = meta[:expires_at]
        return false unless expires_at

        expires_at > Time.now
      end

      def revoke_expired_lease(name, generation:)
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
            next unless lifecycle_current?(generation) && @active_leases[name]&.dig(:lease_id) == lease_id

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

      def trigger_reconnect(name, generation: @generation, active: nil)
        return unless lifecycle_current?(generation, active: active)

        name = name.to_sym if name.respond_to?(:to_sym)
        case name
        when :rabbitmq
          return unless defined?(Legion::Transport::Connection)

          Legion::Transport::Connection.force_reconnect
          log.info("LeaseManager: triggered transport reconnect after '#{name}' reissue")
        when :postgresql
          trigger_postgresql_reconnect(name)
        when :redis
          return unless defined?(Legion::Cache)

          if Legion::Cache.respond_to?(:restart)
            Legion::Cache.restart
          elsif Legion::Cache.respond_to?(:reconnect)
            Legion::Cache.reconnect
          end
          log.info("LeaseManager: triggered cache reconnect after '#{name}' reissue")
        end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.lease_manager.trigger_reconnect', lease_name: name)
        log.error("LeaseManager: reconnect for '#{name}' FAILED: #{e.message} — " \
                  'services may be unavailable until the next lease rotation')
      end

      def trigger_postgresql_reconnect(name)
        unless defined?(Legion::Data::Connection)
          log.debug("LeaseManager: no Legion::Data::Connection loaded for '#{name}' reconnect")
          return
        end

        if Legion::Data::Connection.respond_to?(:reconnect_with_fresh_creds)
          success = Legion::Data::Connection.reconnect_with_fresh_creds
          if success
            log.info("LeaseManager: reconnected data layer with fresh credentials after '#{name}' reissue")
          else
            log.error("LeaseManager: FAILED to reconnect data layer after '#{name}' reissue — " \
                      'Apollo and other DB-backed services may be unavailable')
          end
        elsif Legion::Data::Connection.respond_to?(:sequel) && Legion::Data::Connection.sequel
          log.warn('LeaseManager: legion-data does not support reconnect_with_fresh_creds — ' \
                   'falling back to pool disconnect (may use stale credentials)')
          Legion::Data::Connection.sequel.disconnect
          Legion::Data::Connection.sequel.test_connection
          log.info("LeaseManager: triggered data pool reconnect after '#{name}' reissue (legacy path)")
        else
          log.warn("LeaseManager: no active data connection to reconnect after '#{name}' reissue")
        end
      end

      def with_current_state(generation:, active: nil)
        @state_mutex.synchronize do
          next false unless lifecycle_current?(generation)

          next yield unless active

          result = false
          active.call { result = yield }
          result
        end
      end

      def lifecycle_current?(generation, active: nil)
        !@stopped && generation == @generation &&
          !(Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping) && (!active || active.call)
      end

      def running?(generation: @generation)
        @state_mutex.synchronize { @running && lifecycle_current?(generation) }
      end

      def interruptible_sleep(seconds, generation: @generation)
        deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + seconds
        loop do
          remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
          break if remaining <= 0 || !running?(generation: generation)

          sleep([remaining, 1.0].min)
        end
      end
    end
  end
end
