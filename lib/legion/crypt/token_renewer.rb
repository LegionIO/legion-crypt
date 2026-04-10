# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/kerberos_auth'

module Legion
  module Crypt
    class TokenRenewer
      include Legion::Logging::Helper

      INITIAL_BACKOFF = 30
      MAX_BACKOFF     = 600
      MIN_SLEEP       = 30
      RENEWAL_RATIO   = 0.75

      attr_reader :cluster_name

      def initialize(cluster_name:, config:, vault_client:)
        @cluster_name = cluster_name
        @config       = config
        @vault_client = vault_client
        @thread       = nil
        @stop         = false
        @backoff      = INITIAL_BACKOFF
      end

      def start
        return if running?

        @stop = false
        @thread = Thread.new { renewal_loop }
        @thread.name = "vault-renewer-#{@cluster_name}"
        log.info("TokenRenewer[#{@cluster_name}]: token renewal thread started")
      end

      def stop
        @stop = true
        @thread&.wakeup
      rescue ThreadError => e
        handle_exception(e, level: :debug, operation: 'crypt.token_renewer.stop', cluster_name: @cluster_name)
        nil
      ensure
        stop_thread_and_revoke
      end

      def running?
        @thread&.alive? == true
      end

      def renew_token
        result = @vault_client.auth_token.renew_self
        @config[:lease_duration] = result.auth.lease_duration
        @config[:renewable] = result.auth.renewable? if result.auth.respond_to?(:renewable?)
        log.info("TokenRenewer[#{@cluster_name}]: token renewed, ttl=#{result.auth.lease_duration}s")
        true
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.renew_token', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: token renewal failed: #{e.message}")
        false
      end

      def reauth_kerberos
        krb_config = @config[:kerberos] || {}
        result = Legion::Crypt::KerberosAuth.login(
          vault_client:      @vault_client,
          service_principal: krb_config[:service_principal],
          auth_path:         krb_config[:auth_path] || KerberosAuth::DEFAULT_AUTH_PATH
        )

        @config[:token]          = result[:token]
        @config[:lease_duration] = result[:lease_duration]
        @config[:renewable]      = result[:renewable]
        @config[:connected]      = true
        @vault_client.token      = result[:token]
        log.info("TokenRenewer[#{@cluster_name}]: re-authenticated via Kerberos, ttl=#{result[:lease_duration]}s")

        reissue_all_leases
        true
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.reauth_kerberos', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: Kerberos re-auth failed: #{e.message}")
        false
      end

      def sleep_duration
        lease_duration = @config[:lease_duration].to_i
        duration = [(lease_duration * RENEWAL_RATIO).to_i, 1].max
        return [duration, lease_duration - 1].min if lease_duration.positive? && lease_duration < MIN_SLEEP

        [duration, MIN_SLEEP].max
      end

      def next_backoff
        current = @backoff
        @backoff = [@backoff * 2, MAX_BACKOFF].min
        current
      end

      def reset_backoff
        @backoff = INITIAL_BACKOFF
      end

      private

      def renewal_loop
        interruptible_sleep(sleep_duration)

        until @stop
          if @config[:renewable]
            if renew_token || reauth_kerberos
              on_renewal_success
            else
              on_renewal_failure
            end
          else
            if reauth_kerberos # rubocop:disable Style/IfInsideElse
              on_renewal_success
            else
              on_renewal_failure
            end
          end
        end
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.renewal_loop', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: renewal loop error: #{e.message}")
        retry unless @stop
      end

      def on_renewal_success
        reset_backoff
        interruptible_sleep(sleep_duration)
      end

      def on_renewal_failure
        @config[:connected] = false
        delay = next_backoff
        log.warn("TokenRenewer[#{@cluster_name}]: backoff retry in #{delay}s")
        interruptible_sleep(delay)
      end

      def reissue_all_leases
        return unless defined?(Legion::Crypt::LeaseManager)

        Legion::Crypt::LeaseManager.instance.reissue_all
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.reissue_all_leases', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: failed to reissue leases after reauth: #{e.message}")
      end

      def interruptible_sleep(seconds)
        deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + seconds
        loop do
          remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
          break if remaining <= 0 || @stop

          sleep([remaining, 1.0].min)
        end
      end

      def stop_thread_and_revoke
        return unless @thread

        log.info("TokenRenewer[#{@cluster_name}]: stopping token renewal thread")
        @thread.join(5)
        thread_still_running = @thread.alive?

        if thread_still_running
          log.warn("TokenRenewer[#{@cluster_name}]: token renewal thread did not stop within timeout; skipping token revocation")
        else
          @thread = nil
          revoke_token
          log.info("TokenRenewer[#{@cluster_name}]: token renewal thread stopped")
        end
      end

      def revoke_token
        return unless @vault_client&.token
        return unless @config[:auth_method]&.to_s == 'kerberos'

        @vault_client.auth_token.revoke_self
        log.info("TokenRenewer[#{@cluster_name}]: Vault token revoked")
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.token_renewer.revoke_token', cluster_name: @cluster_name)
        log.warn("TokenRenewer[#{@cluster_name}]: Vault token revoke failed: #{e.message}")
      end
    end
  end
end
