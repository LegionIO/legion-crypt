# frozen_string_literal: true

require 'legion/crypt/kerberos_auth'

module Legion
  module Crypt
    class TokenRenewer
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
        @stop = false
        @thread = Thread.new { renewal_loop }
        @thread.name = "vault-renewer-#{@cluster_name}"
        log_debug('token renewal thread started')
      end

      def stop
        @stop = true
        @thread&.wakeup
      rescue ThreadError
        nil
      ensure
        @thread&.join(5)
        @thread = nil
        revoke_token
        log_debug('token renewal thread stopped')
      end

      def running?
        @thread&.alive? == true
      end

      def renew_token
        result = @vault_client.auth_token.renew_self
        @config[:lease_duration] = result.auth.lease_duration
        log_debug("token renewed, ttl=#{result.auth.lease_duration}s")
        true
      rescue StandardError => e
        log_warn("token renewal failed: #{e.message}")
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
        log_info('re-authenticated via Kerberos')
        true
      rescue StandardError => e
        log_warn("Kerberos re-auth failed: #{e.message}")
        false
      end

      def sleep_duration
        duration = (@config[:lease_duration].to_i * RENEWAL_RATIO).to_i
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
          if renew_token || reauth_kerberos
            on_renewal_success
          else
            on_renewal_failure
          end
        end
      rescue StandardError => e
        log_warn("renewal loop error: #{e.message}")
        retry unless @stop
      end

      def on_renewal_success
        reset_backoff
        interruptible_sleep(sleep_duration)
      end

      def on_renewal_failure
        @config[:connected] = false
        delay = next_backoff
        log_warn("backoff retry in #{delay}s")
        interruptible_sleep(delay)
      end

      def interruptible_sleep(seconds)
        deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + seconds
        loop do
          remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
          break if remaining <= 0 || @stop

          sleep([remaining, 1.0].min)
        end
      end

      def revoke_token
        return unless @vault_client&.token
        return unless @config[:auth_method]&.to_s == 'kerberos'

        @vault_client.auth_token.revoke_self
        log_info('Vault token revoked')
      rescue StandardError => e
        log_warn("Vault token revoke failed: #{e.message}")
      end

      def log_debug(message)
        Legion::Logging.debug("TokenRenewer[#{@cluster_name}]: #{message}") if defined?(Legion::Logging)
      end

      def log_info(message)
        Legion::Logging.info("TokenRenewer[#{@cluster_name}]: #{message}") if defined?(Legion::Logging)
      end

      def log_warn(message)
        Legion::Logging.warn("TokenRenewer[#{@cluster_name}]: #{message}") if defined?(Legion::Logging)
      end
    end
  end
end
