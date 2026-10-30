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
      MINIMUM_SLEEP = 0.01
      MAX_RETRY_DELAY = 60

      def initialize
        @lease_cache = {}
        @active_leases = {}
        @owned_leases = {}
        @pending = {}
        @refs = {}
        @lease_locks = {}
        @state_mutex = Mutex.new
        @wake = ConditionVariable.new
        @running = false
        @renewal_thread = nil
        @generation = 0
        @stopped = false
        @renewal_generation = nil
      end

      def start(definitions, vault_client: nil)
        client = vault_client || Legion::Crypt.vault_client
        generation = @state_mutex.synchronize do
          return if Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping

          @stopped = false
          @vault_client = client
          @generation
        end
        register_at_exit_hook
        (definitions || {}).each do |name, opts|
          break unless lifecycle_current?(generation)

          name = name.to_sym
          path = opts['path'] || opts[:path]
          next unless path

          pending = @state_mutex.synchronize { @pending[name] }
          next if lease_valid?(name, path: path, client: client)
          next if pending && pending[:path] == path && pending[:client].equal?(client) && pending[:next_attempt_at] > monotonic_now

          acquire_lease(name: name, path: path, client: client, generation: generation)
        end
      end

      def fetched_count
        @state_mutex.synchronize { @active_leases.size }
      end

      def fetch(name, key)
        data = lease_data(name)
        return unless data

        data.key?(key.to_sym) ? data[key.to_sym] : data[key.to_s]
      end

      def lease_data(name)
        @state_mutex.synchronize { @lease_cache[name.to_sym] }
      end

      attr_reader :active_leases

      def register_ref(name, key, path, generation: @generation)
        return false unless path.is_a?(Array) && !path.empty?

        with_current_state(generation: generation) do
          @refs[name.to_sym] ||= {}
          destinations = (@refs[name.to_sym][key.to_sym] ||= [])
          destinations << path.dup.freeze unless destinations.include?(path)
        end
      end

      def push_to_settings(name, generation: @generation, active: nil)
        count = with_current_state(generation: generation, active: active) do
          refs = @refs[name.to_sym]
          data = @lease_cache[name.to_sym]
          next 0 if refs.nil? || refs.empty? || data.nil?

          refs.sum do |key, paths|
            next 0 unless data.key?(key) || data.key?(key.to_s)

            value = data.key?(key) ? data[key] : data[key.to_s]
            paths.count { |path| write_setting(path, value) }
          end
        end
        return unless count

        log.info("Lease '#{name}' rotated — updated #{count} settings reference(s)")
        count
      end

      def vault_logical
        client = @state_mutex.synchronize { @vault_client } || Legion::Crypt.vault_client
        client.logical
      end

      def vault_sys
        client = @state_mutex.synchronize { @vault_client } || Legion::Crypt.vault_client
        client.sys
      end

      def reissue_all(active: nil)
        names, generation = @state_mutex.synchronize { [@active_leases.keys, @generation] }
        names.each do |name|
          break unless lifecycle_current?(generation, active: active)

          reissue_lease(name, generation: generation, active: active)
        end
      end

      def register_dynamic_lease(name:, path:, response:, settings_refs:)
        name = name.to_sym
        generation, client = @state_mutex.synchronize { [@generation, @vault_client] }
        client ||= Legion::Crypt.vault_client
        register_at_exit_hook
        ownership = track_ownership(name: name, client: client, lease_id: response.lease_id)
        install_started = false
        with_lease_operation(name: name) do |deadline|
          settings_refs.each { |ref| register_ref(name, ref[:key], ref[:path], generation: generation) }
          install_started = true
          install_lease(name: name, path: path, response: response, client: client, generation: generation,
                        deadline: deadline, reconnect: true, ownership: ownership)
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.register_dynamic_lease', lease_name: name)
        unless install_started
          @state_mutex.synchronize do
            entry = @owned_leases[ownership]
            entry[:retired] = true if entry && @active_leases[name]&.dig(:ownership) != ownership
          end
        end
        schedule_retry(name: name, path: path, client: client, generation: generation)
        false
      end

      def reissue_lease(name, generation: @generation, active: nil, deadline: nil)
        name = name.to_sym
        lease = @state_mutex.synchronize { @active_leases[name]&.dup }
        return false unless lease && lease[:path] && lifecycle_current?(generation, active: active)

        acquire_lease(name: name, path: lease[:path], client: lease[:client], generation: generation,
                      active: active, deadline: deadline, lease: lease)
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
        @state_mutex.synchronize do
          @stopped = true
          @running = false
          @generation += 1
          @lease_locks.clear
          @wake.broadcast
          @renewal_thread
        end
      end

      def shutdown(deadline: nil)
        deadline ||= monotonic_now + Legion::Crypt::VaultOperation::SHUTDOWN_TIMEOUT
        request_stop
        @state_mutex.synchronize do
          @active_leases.clear
          @lease_cache.clear
          @refs.clear
          @pending.clear
          @vault_client = nil
          @owned_leases.each_value { |entry| entry[:retired] = true }
        end
        stop_renewal_thread(deadline: deadline)
        retire_unused_leases(deadline: deadline, force: true)
        log.info 'LeaseManager shutdown complete'
      end

      def reset!
        stop_renewal_thread
        @state_mutex.synchronize do
          @lease_cache.clear
          @active_leases.clear
          @owned_leases.clear
          @pending.clear
          @refs.clear
          @vault_client = nil
          @stopped = false
        end
      end

      private

      def register_at_exit_hook
        return if @at_exit_registered

        at_exit do
          next if @state_mutex.synchronize { @owned_leases.empty? }

          shutdown
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.lease_manager.at_exit')
        end
        @at_exit_registered = true
      end

      def monotonic_now
        ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
      end

      def with_lease_operation(name:, deadline: nil)
        lock = @state_mutex.synchronize { @lease_locks[name] ||= Mutex.new }
        Legion::Crypt::VaultOperation.with_timeout(deadline: deadline) do |operation_deadline|
          lock.synchronize { yield operation_deadline }
        end
      end

      def lease_operation_current?(name:, pending: nil, lease: nil)
        @state_mutex.synchronize do
          next false if pending && !@pending[name].equal?(pending)

          lease.nil? || @active_leases.dig(name, :ownership) == lease[:ownership]
        end
      end

      def acquire_lease(name:, path:, client:, generation:, **options)
        active = options[:active]
        deadline = options[:deadline]
        with_lease_operation(name: name, deadline: deadline) do |operation_deadline|
          return false unless lifecycle_current?(generation, active: active)
          return false unless lease_operation_current?(name: name, pending: options[:pending], lease: options[:lease])
          raise ArgumentError, 'Lease acquisition requires a path' unless path

          response = client.logical.read(path: path)
          raise "Vault returned no lease for #{name}" unless response

          install_lease(name: name, path: path, response: response, client: client, generation: generation,
                        active: active, deadline: operation_deadline)
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.acquire_lease', lease_name: name, path: path)
        schedule_retry(name: name, path: path, client: client, generation: generation, active: active,
                       pending: options[:pending], lease: options[:lease])
        false
      end

      def track_ownership(name:, client:, lease_id:)
        return if lease_id.nil? || lease_id.empty?

        key = [client, lease_id]
        @state_mutex.synchronize do
          @owned_leases[key] ||= { name: name, client: client, lease_id: lease_id, retired: false,
                                  revoking: false, attempts: 0, next_attempt_at: 0 }
        end
        key
      end

      def install_lease(name:, path:, response:, client:, **context)
        lease_id = context.fetch(:lease_id) { response.lease_id }
        ownership = context.fetch(:ownership) { track_ownership(name: name, client: client, lease_id: lease_id) }
        handoff = { name: name, ownership: ownership, context: context }
        now = Time.now
        ttl = response.lease_duration || 0
        candidate = { lease_id: lease_id, lease_duration: ttl, renewable: response.renewable?,
                      expires_at: ttl.positive? ? now + ttl : nil, fetched_at: now, path: path,
                      client: client, ownership: ownership }
        handoff[:candidate] = candidate
        handoff[:data] = context.fetch(:data) { response.data }
        return false unless stage_install(handoff: handoff)

        generation = context.fetch(:generation)
        active = context[:active]
        handoff[:attempted_reconnect] = handoff[:reconnect]
        raise "Lease consumer reconnect failed for #{name}" if handoff[:reconnect] && !trigger_reconnect(name, generation: generation, active: active)

        committed = with_current_state(generation: generation, active: active) do
          next false unless @active_leases[name].equal?(candidate)

          @pending.delete(name)
          @owned_leases.each do |key, entry|
            entry[:retired] = true if entry[:name] == name && key != ownership
          end
          @wake.broadcast
          true
        end
        committed
      ensure
        abort_install(handoff: handoff) if handoff && !committed
        retire_unused_leases(name: name, deadline: context[:deadline])
      end

      def stage_install(handoff:)
        name = handoff[:name]
        data = handoff[:data]
        context = handoff[:context]

        with_current_state(generation: context.fetch(:generation), active: context[:active]) do
          validate_lease_data!(name: name, data: data, require_credentials: context[:reconnect] || @refs.dig(name, :password))
          owner = @owned_leases[handoff[:ownership]]
          raise 'Lease candidate is being revoked or has already been retired' if handoff[:ownership] && (!owner || owner[:revoking])

          owner[:retired] = false if owner

          previous = @active_leases[name]
          snapshots = setting_snapshots(name: name, data: data)
          transaction = { previous: previous, data: @lease_cache[name], settings: snapshots, candidate: handoff[:candidate] }
          handoff[:transaction] = transaction
          snapshots.each { |target, key, _old, value| target[key] = value }
          @lease_cache[name] = data
          @active_leases[name] = handoff[:candidate]
          handoff[:reconnect] = context[:reconnect] || (previous && transaction[:data] != data) || !snapshots.empty?
          true
        end
      end

      def validate_lease_data!(name:, data:, require_credentials:)
        raise "Vault returned invalid lease data for #{name}" unless data.is_a?(Hash)
        return unless name == :rabbitmq && require_credentials

        username = data[:username] || data['username']
        password = data[:password] || data['password']
        raise 'RabbitMQ lease requires username and password' unless username && password
      end

      def abort_install(handoff:)
        name = handoff[:name]
        context = handoff[:context]
        generation = context.fetch(:generation)
        active = context[:active]
        ownership = handoff[:ownership]
        restored = rollback_install(name: name, transaction: handoff[:transaction], generation: generation, active: active)
        safe_to_retire = !handoff[:attempted_reconnect] || !lifecycle_current?(generation, active: active)
        if handoff[:attempted_reconnect] && restored
          begin
            safe_to_retire = Legion::Crypt::VaultOperation.with_timeout(deadline: context[:deadline]) do
              trigger_reconnect(name, generation: generation, active: active)
            end
          rescue StandardError => e
            handle_exception(e, level: :warn, operation: 'crypt.lease_manager.rollback_reconnect', lease_name: name)
          end
        end
        @state_mutex.synchronize do
          entry = @owned_leases[ownership]
          entry[:retired] = true if entry && safe_to_retire && @active_leases[name]&.dig(:ownership) != ownership
        end
      end

      def setting_snapshots(name:, data:)
        (@refs[name] || {}).flat_map do |key, paths|
          raise "Lease #{name} omitted referenced key #{key}" unless data.key?(key) || data.key?(key.to_s)

          value = data.key?(key) ? data[key] : data[key.to_s]
          paths.map do |path|
            target, segment = setting_target(path)
            raise "Lease #{name} has an unwritable settings destination #{path.inspect}" unless target

            [target, segment, target[segment], value]
          end
        end
      end

      def rollback_install(name:, transaction:, generation:, active:)
        return false unless transaction

        with_current_state(generation: generation, active: active) do
          current = @active_leases[name]
          next false unless current.equal?(transaction[:candidate]) || current.equal?(transaction[:previous])

          transaction[:settings].each do |target, key, previous, candidate|
            target[key] = previous if target[key] == candidate
          end
          if transaction[:previous]
            @active_leases[name] = transaction[:previous]
            @lease_cache[name] = transaction[:data]
          else
            @active_leases.delete(name)
            @lease_cache.delete(name)
          end
          true
        end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.lease_manager.rollback_install', lease_name: name)
        false
      end

      def schedule_retry(name:, path:, client:, generation:, **options)
        with_current_state(generation: generation, active: options[:active]) do
          previous = @pending[name]
          next false if options[:pending] && !previous.equal?(options[:pending])
          next false if options[:lease] && @active_leases.dig(name, :ownership) != options[:lease][:ownership]

          attempts = previous && previous[:path] == path && previous[:client].equal?(client) ? previous[:attempts] : 0
          attempts = [attempts + 1, 7].min
          @pending[name] = { path: path, client: client, operation: options.fetch(:operation, :acquire), attempts: attempts,
                             next_attempt_at: monotonic_now + [2**(attempts - 1), MAX_RETRY_DELAY].min }
          @wake.broadcast
        end
      end

      def retire_unused_leases(name: nil, deadline: nil, force: false)
        keys = @state_mutex.synchronize do
          @owned_leases.filter_map do |key, entry|
            key if entry[:retired] && (!name || entry[:name] == name) && (force || entry[:next_attempt_at] <= monotonic_now)
          end
        end
        keys.each { |key| revoke_owned_lease(key: key, deadline: deadline) }
      end

      def revoke_owned_lease(key:, deadline:)
        entry = @state_mutex.synchronize do
          item = @owned_leases[key]
          next unless item && item[:retired] && !item[:revoking]
          next if @active_leases.any? { |_name, lease| lease[:ownership] == key }

          item[:revoking] = true
          item
        end
        return unless entry

        Legion::Crypt::VaultOperation.with_timeout(deadline: deadline) { entry[:client].sys.revoke(lease_id: entry[:lease_id]) }
        @state_mutex.synchronize { @owned_leases.delete(key) if @owned_leases[key].equal?(entry) }
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.revoke_owned_lease', lease_name: entry&.dig(:name))
        @state_mutex.synchronize do
          if entry && @owned_leases[key].equal?(entry)
            entry[:attempts] = [entry[:attempts] + 1, 7].min
            entry[:next_attempt_at] = monotonic_now + [2**(entry[:attempts] - 1), MAX_RETRY_DELAY].min
          end
        end
      ensure
        @state_mutex.synchronize { entry[:revoking] = false if entry }
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
        while running?(generation: generation)
          renew_approaching_leases(generation: generation)
          interruptible_sleep(generation: generation)
        end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.lease_manager.renewal_loop')
        interruptible_sleep(RENEWAL_CHECK_INTERVAL, generation: generation)
        retry if running?(generation: generation)
      end

      # Called while holding @state_mutex, immediately before the condition wait.
      def next_maintenance_delay
        delays = @pending.values.map { |entry| entry[:next_attempt_at] - monotonic_now }
        @active_leases.each do |name, lease|
          delays << renewal_delay(lease) unless @pending.key?(name)
        end
        @owned_leases.each do |key, entry|
          next unless entry[:retired] && !entry[:revoking]
          next if @active_leases.each_value.any? { |lease| lease[:ownership] == key }

          delays << (entry[:next_attempt_at] - monotonic_now)
        end
        (delays.min || RENEWAL_CHECK_INTERVAL).clamp(MINIMUM_SLEEP, RENEWAL_CHECK_INTERVAL)
      end

      def renew_approaching_leases(generation: @generation)
        leases = @state_mutex.synchronize { @active_leases.to_a.sort_by { |_name, lease| renewal_delay(lease) } }
        attempted = []
        leases.each do |name, lease|
          break unless lifecycle_current?(generation)
          next if @state_mutex.synchronize { @pending.key?(name) }
          next if renewal_delay(lease).positive?

          attempted << name
          if lease_renewable?(lease: lease)
            renew_lease(name, lease.dup, generation: generation)
          else
            acquire_lease(name: name, path: lease[:path], client: lease[:client], generation: generation, lease: lease)
          end
        end
        pending = @state_mutex.synchronize { @pending.to_a }
        pending.each do |name, entry|
          break unless lifecycle_current?(generation)
          next if attempted.include?(name) || entry[:next_attempt_at] > monotonic_now

          lease = @state_mutex.synchronize { @active_leases[name]&.dup }
          if entry[:operation] == :renew && lease_renewable?(lease: lease)
            renew_lease(name, lease, generation: generation, pending: entry)
          else
            acquire_lease(name: name, path: entry[:path], client: entry[:client], generation: generation, pending: entry, lease: lease)
          end
        end
        retire_unused_leases if lifecycle_current?(generation)
      end

      def renew_lease(name, lease, generation: @generation, pending: nil)
        name = name.to_sym
        operation_deadline = nil
        with_lease_operation(name: name) do |deadline|
          operation_deadline = deadline
          return false unless lifecycle_current?(generation)
          return false unless lease_operation_current?(name: name, pending: pending, lease: lease)

          raise 'Lease cannot be renewed without an ID' if lease[:lease_id].to_s.empty?

          response = lease[:client].sys.renew(lease_id: lease[:lease_id])
          raise 'Lease renewal did not return a positive TTL' unless response&.lease_duration&.positive?

          data = response.data
          data = @state_mutex.synchronize { @lease_cache[name] } if data.nil? || data.empty?
          lease_id = response.lease_id.to_s.empty? ? lease[:lease_id] : response.lease_id
          ownership = if lease_id == lease[:lease_id]
                        lease[:ownership]
                      else
                        track_ownership(name: name, client: lease[:client], lease_id: lease_id)
                      end
          install_lease(name: name, path: lease[:path], response: response, client: lease[:client], generation: generation,
                        deadline: deadline, data: data, lease_id: lease_id, ownership: ownership)
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.renew_lease', lease_name: name)
        return reissue_lease(name, generation: generation, deadline: operation_deadline) if operation_deadline && !e.is_a?(Timeout::Error) && lease[:path]

        schedule_retry(name: name, path: lease[:path], client: lease[:client], generation: generation, operation: :renew, pending: pending)
        false
      end

      def lease_valid?(name, path:, client:)
        lease = @state_mutex.synchronize { @active_leases[name.to_sym] }
        lease && lease[:path] == path && lease[:client].equal?(client) && lease_unexpired?(lease: lease)
      end

      def lease_unexpired?(lease:)
        lease[:expires_at].nil? || lease[:expires_at] > Time.now
      end

      def lease_renewable?(lease:)
        lease && lease[:renewable] && lease_unexpired?(lease: lease)
      end

      def renewal_delay(lease)
        ttl = lease[:lease_duration] || 0
        return lease[:fetched_at] + RENEWAL_CHECK_INTERVAL - Time.now unless ttl.positive?
        return 0 unless lease[:expires_at]

        lease[:expires_at] - Time.now - (ttl * 0.5)
      end

      def setting_target(path)
        return unless path.is_a?(Array) && !path.empty?

        target = Legion::Settings.get.settings
        path.each_with_index do |segment, index|
          valid =
            case target
            when Hash then segment.is_a?(Symbol) && target.key?(segment)
            when Array then segment.is_a?(Integer) && segment >= 0 && segment < target.length
            end
          return nil unless valid
          return target.frozen? ? nil : [target, segment] if index == path.length - 1

          target = target[segment]
        end
      end

      def write_setting(path, value)
        target, key = setting_target(path)
        return false unless target

        target[key] = value
        true
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.lease_manager.write_setting', path: path.inspect)
        false
      end

      def trigger_reconnect(name, generation: @generation, active: nil)
        return false unless lifecycle_current?(generation, active: active)

        case name.to_sym
        when :rabbitmq
          return true unless defined?(Legion::Transport::Connection)

          connection = Legion::Transport::Connection
          connection.force_reconnect == true && connection.session_open?
        when :postgresql
          return true unless defined?(Legion::Data::Connection)

          connection = Legion::Data::Connection
          connection.respond_to?(:reconnect_with_fresh_creds) && connection.reconnect_with_fresh_creds == true
        when :redis
          return true unless defined?(Legion::Cache)

          cache = Legion::Cache
          result = if cache.respond_to?(:restart)
                     cache.restart
                   elsif cache.respond_to?(:reconnect)
                     cache.reconnect
                   end
          result == true && (!cache.respond_to?(:connected?) || cache.connected?)
        else
          true
        end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.lease_manager.trigger_reconnect', lease_name: name)
        false
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

      def interruptible_sleep(seconds = nil, generation: @generation)
        @state_mutex.synchronize do
          @wake.wait(@state_mutex, seconds || next_maintenance_delay) if @running && lifecycle_current?(generation)
        end
      end
    end
  end
end
