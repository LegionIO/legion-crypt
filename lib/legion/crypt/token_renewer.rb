# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/kerberos_auth'
require 'legion/crypt/vault_operation'
require 'legion/crypt/vault_client'

module Legion
  module Crypt
    class TokenRenewer
      include Legion::Logging::Helper

      INITIAL_BACKOFF = 30
      MAX_BACKOFF     = 600
      MIN_SLEEP       = 30
      RENEWAL_RATIO   = 0.75
      MINIMUM_WAIT = 0.01

      attr_reader :cluster_name

      def initialize(cluster_name:, config:, vault_client:)
        @cluster_name = cluster_name
        @config       = config
        @vault_client = vault_client
        @thread       = nil
        @stop         = false
        @backoff      = INITIAL_BACKOFF
        @state_mutex  = Mutex.new
        @wake         = ConditionVariable.new
        @generation   = 0
        @stopping     = false
        ttl = config[:lease_duration].to_f
        @expires_at = config[:expires_at] || (Time.now + ttl if ttl.positive?)
        @renewal_terminal = false
      end

      def start
        @state_mutex.synchronize do
          return if @stopping || @thread&.alive? || crypt_stopping?

          @stop = false
          @generation += 1
          generation = @generation
          @thread = Thread.new { renewal_loop(generation: generation) }
          @thread.name = "vault-renewer-#{@cluster_name}"
        end
        log.info("TokenRenewer[#{@cluster_name}]: token renewal thread started")
      end

      def request_stop
        @state_mutex.synchronize do
          @stop = true
          @generation += 1
          @wake.broadcast
        end
        nil
      end

      def stop(deadline: nil)
        deadline ||= ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + VaultOperation::SHUTDOWN_TIMEOUT
        @state_mutex.synchronize do
          return if @stopping

          @stopping = true
        end

        begin
          request_stop
          thread = @state_mutex.synchronize { @thread }
          stop_thread_and_revoke(thread: thread, deadline: deadline)
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.token_renewer.stop', cluster_name: @cluster_name)
        ensure
          @state_mutex.synchronize { @stopping = false }
        end
      end

      def running?
        @state_mutex.synchronize { @thread&.alive? == true }
      end

      def renew_token(generation: nil)
        generation ||= @state_mutex.synchronize { @generation }
        return false unless @state_mutex.synchronize { active_generation?(generation: generation) }

        deadline = @state_mutex.synchronize do
          ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + (@expires_at - Time.now) if @expires_at
        end
        VaultOperation.with_timeout(deadline: deadline) do
          result = @vault_client.auth_token.renew_self
          @state_mutex.synchronize do
            return false unless active_generation?(generation: generation)

            @config[:lease_duration] = result.auth.lease_duration
            @config[:renewable] = result.auth.renewable? if result.auth.respond_to?(:renewable?)
            ttl = result.auth.lease_duration.to_f
            @expires_at = ttl.positive? ? Time.now + ttl : nil
            @config[:expires_at] = @expires_at
            @config[:connected] = true
            @config[:relogin_required] = false
          end
          log.info("TokenRenewer[#{@cluster_name}]: token renewed, ttl=#{result.auth.lease_duration}s")
          true
        end
      rescue StandardError => e
        @state_mutex.synchronize do
          if active_generation?(generation: generation) && @config[:auth_method].to_s == 'ldap'
            @renewal_terminal = e.is_a?(Legion::Crypt::Vault::HTTPClientError) && ![408, 429].include?(e.code)
            if @renewal_terminal || (@expires_at && @expires_at <= Time.now)
              @config[:connected] = false
              @config[:relogin_required] = true
            end
          end
        end
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.renew_token', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: token renewal failed: #{e.message}")
        false
      end

      def reauth_kerberos(generation: nil)
        generation ||= @state_mutex.synchronize { @generation }
        krb_config = @state_mutex.synchronize do
          return false unless active_generation?(generation: generation)
          return false unless @config[:auth_method].to_s == 'kerberos'

          (@config[:kerberos] || {}).dup
        end
        active = lambda do |&mutation|
          @state_mutex.synchronize do
            next false unless active_generation?(generation: generation)

            mutation&.call
            true
          end
        end
        VaultOperation.with_timeout do
          result = Legion::Crypt::KerberosAuth.login(
            vault_client:      @vault_client,
            service_principal: krb_config[:service_principal],
            auth_path:         krb_config[:auth_path] || KerberosAuth::DEFAULT_AUTH_PATH,
            principal_guard:   active
          )

          @state_mutex.synchronize do
            return false unless active_generation?(generation: generation)

            Legion::Crypt.publish_vault_token(client: @vault_client, config: @config, token: result[:token])
            @config[:lease_duration] = result[:lease_duration]
            @config[:renewable]      = result[:renewable]
            @config[:connected]      = true
            ttl = result[:lease_duration].to_f
            @expires_at = ttl.positive? ? Time.now + ttl : nil
            @config[:expires_at] = @expires_at
            @config[:relogin_required] = false
          end
          log.info("TokenRenewer[#{@cluster_name}]: re-authenticated via Kerberos, ttl=#{result[:lease_duration]}s")
        end
        reissue_all_leases(active: active)
        true
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.reauth_kerberos', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: Kerberos re-auth failed: #{e.message}")
        false
      end

      def sleep_duration
        @state_mutex.synchronize do
          return MIN_SLEEP unless @expires_at

          remaining = @expires_at - Time.now
          renewable = @config[:renewable] || @config[:auth_method].to_s == 'kerberos'
          delay = renewable ? remaining - (@config[:lease_duration].to_f * (1 - RENEWAL_RATIO)) : remaining
          [delay, MINIMUM_WAIT].max
        end
      end

      def next_backoff(generation: nil)
        @state_mutex.synchronize do
          return unless active_generation?(generation: generation || @generation)

          current = @backoff
          @backoff = [@backoff * 2, MAX_BACKOFF].min
          current
        end
      end

      def reset_backoff(generation: nil)
        @state_mutex.synchronize do
          return unless active_generation?(generation: generation || @generation)

          @backoff = INITIAL_BACKOFF
        end
      end

      private

      def crypt_stopping?
        Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping
      end

      def active_generation?(generation:)
        !@stop && !crypt_stopping? && @generation == generation
      end

      def renewal_loop(generation:)
        interruptible_sleep(sleep_duration, generation: generation)

        loop do
          policy = renewal_policy(generation: generation)
          return unless policy

          renewable, kerberos = policy
          renewed = (renewable && renew_token(generation: generation)) || (kerberos && reauth_kerberos(generation: generation))
          return unless @state_mutex.synchronize { active_generation?(generation: generation) }

          if renewed
            on_renewal_success(generation: generation)
          else
            on_renewal_failure(generation: generation)
          end
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.renewal_loop', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: renewal loop error: #{e.message}")
        on_renewal_failure(generation: generation)
        retry if @state_mutex.synchronize { active_generation?(generation: generation) }
      end

      def renewal_policy(generation:)
        @state_mutex.synchronize do
          return unless active_generation?(generation: generation)

          kerberos = @config[:auth_method].to_s == 'kerberos'
          if @expires_at && @expires_at <= Time.now
            @config[:connected] = false
            @config[:relogin_required] = true unless kerberos
            return unless kerberos
          end
          return if !kerberos && (!@config[:renewable] || @config[:relogin_required])

          [@config[:renewable], kerberos]
        end
      end

      def on_renewal_success(generation:)
        return unless reset_backoff(generation: generation)

        interruptible_sleep(sleep_duration, generation: generation)
      end

      def on_renewal_failure(generation:)
        delay = next_backoff(generation: generation)
        return unless delay

        @state_mutex.synchronize do
          return unless active_generation?(generation: generation)

          kerberos = @config[:auth_method].to_s == 'kerberos'
          remaining = @expires_at && (@expires_at - Time.now)
          if kerberos || @renewal_terminal || (remaining && !remaining.positive?)
            @config[:connected] = false
            @config[:relogin_required] = true unless kerberos
          end
          return if !kerberos && @config[:relogin_required]

          delay = [delay, [remaining / 2, MINIMUM_WAIT].max, remaining].min if remaining&.positive?
        end
        log.warn("TokenRenewer[#{@cluster_name}]: backoff retry in #{delay}s")
        interruptible_sleep(delay, generation: generation)
      end

      def reissue_all_leases(active:)
        return unless defined?(Legion::Crypt::LeaseManager)
        return unless active.call

        Legion::Crypt::LeaseManager.instance.reissue_all(active: active)
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.reissue_all_leases', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: failed to reissue leases after reauth: #{e.message}")
      end

      def interruptible_sleep(seconds, generation:)
        deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + seconds
        @state_mutex.synchronize do
          while active_generation?(generation: generation)
            remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
            break unless remaining.positive?

            @wake.wait(@state_mutex, remaining)
          end
        end
      end

      def stop_thread_and_revoke(thread:, deadline:)
        return unless thread

        log.info("TokenRenewer[#{@cluster_name}]: stopping token renewal thread")
        remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
        thread.join(remaining) if remaining.positive? && thread != Thread.current

        if thread.alive?
          log.warn("TokenRenewer[#{@cluster_name}]: token renewal thread did not stop within timeout; skipping token revocation")
        else
          @state_mutex.synchronize { @thread = nil if @thread == thread }
          revoke_token(deadline: deadline)
          log.info("TokenRenewer[#{@cluster_name}]: token renewal thread stopped")
        end
      end

      def revoke_token(deadline: nil)
        owned_token = @state_mutex.synchronize do
          @config[:auth_method]&.to_s == 'kerberos' && @vault_client&.token
        end
        return unless owned_token

        VaultOperation.with_timeout(deadline: deadline) { @vault_client.auth_token.revoke_self }
        log.info("TokenRenewer[#{@cluster_name}]: Vault token revoked")
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.revoke_token', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: Vault token revoke failed: #{e.message}")
      end
    end
  end
end
