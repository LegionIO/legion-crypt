# frozen_string_literal: true

require 'time'
require 'faraday'
require 'legion/logging/helper'
require 'legion/crypt/vault/client'
require 'legion/crypt/vault/auth'
require 'legion/crypt/vault/leases'
require 'legion/crypt/vault/operation'

module Legion
  module Crypt
    module Vault
      # Owns one cluster's token + leases lifecycle. Composes a Vault::Auth strategy (the token)
      # and a Vault::Leases (the dynamic secrets it issues under that token). One maintenance
      # thread drives token renewal and the re-auth -> reissue -> reconnect -> commit/rollback
      # handoff (a single decision point); the leases run their own renewal thread. One instance
      # per cluster, keyed by cluster_name.
      class Session
        include Legion::Logging::Helper

        RENEWAL_RATIO        = 0.75
        INITIAL_BACKOFF      = 30
        MAX_BACKOFF          = 600
        MINIMUM_WAIT         = 0.01
        RENEWAL_CHECK_INTERVAL = 5
        RETRYABLE_CODES      = [408, 429].freeze
        FAILURES             = [IOError, SystemCallError, Timeout::Error, Faraday::Error,
                                Legion::Crypt::Vault::HTTPError].freeze

        attr_reader :cluster_name, :client, :leases

        def initialize(cluster_name:, client:, lease_defs: nil, **)
          @cluster_name = cluster_name
          @client = client
          @lease_defs = lease_defs
          @auth = nil
          @leases = nil
          @auth_method = nil
          @lease_duration = 0
          @renewable = false
          @current_token = nil
          @expires_at = nil
          @rejected = false
          @disconnected = false
          @backoff = INITIAL_BACKOFF
          @stop = false
          @started = false
          @thread = nil
          @state_mutex = Mutex.new
          @wake = ConditionVariable.new
        end

        # Authenticates (Kerberos) or adopts the configured token, publishes the grant, and starts
        # lease acquisition plus the maintenance thread. LDAP/JWT clusters wait for an explicit login.
        def start(**)
          @state_mutex.synchronize do
            return false if @stop || @started

            @started = true
            @auth_method = cluster_config[:auth_method]&.to_s
            authenticate if @auth_method == 'kerberos'
            adopt_config_token if @auth_method.nil? || @auth_method.empty?
            start_maintenance if @current_token
            true
          end
        end

        # Explicit login (LDAP/JWT): authenticate with the given credentials, publish, start maintenance.
        def login(**creds)
          @state_mutex.synchronize do
            raise Legion::Crypt::Vault::GrantRejectedError, 'session is stopped' if @stop

            auth.authenticate(client: @client, **creds)
            publish
            @started = true
            start_maintenance
            @auth.grant
          end
        end

        # Stops the maintenance thread, shuts down the leases, then revokes the token.
        def stop(deadline:, **)
          request_stop
          thread = @state_mutex.synchronize { @thread }
          if thread && thread != Thread.current
            remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
            thread.join(remaining) if remaining.positive?
          end
          @leases&.shutdown(deadline: deadline)
          revoke_token if revocable?
          log.info "Vault session stopped cluster=#{label}"
        end

        def running?
          @state_mutex.synchronize { @thread&.alive? == true }
        end

        # Whether the current token may still be valid (not rejected and not expired).
        def revocable?
          @state_mutex.synchronize { !@rejected && (@expires_at.nil? || @expires_at > Time.now) }
        end

        # The authenticated principal (from the grant's metadata), if any.
        def principal
          grant = @auth&.grant
          return nil if grant.nil?

          grant.metadata&.dig(:username)
        end

        # Called (as a 0-arg callable or with a block) to test/drive work while this session is the
        # live grant owner. Used by Vault::Leases#reissue_all during the handoff.
        def grant_active
          @state_mutex.synchronize do
            next false if @stop || !@started || crypt_stopping?

            yield if block_given?
            true
          end
        end

        private

        def label
          @cluster_name || 'default'
        end

        def crypt_stopping?
          Legion::Crypt.respond_to?(:stopping) && Legion::Crypt.stopping
        end

        # The effective config for this cluster: the named cluster's settings, or the top-level
        # vault settings for the single-cluster (nil) case. A named cluster that is not configured
        # is a configuration error, not a fallback.
        def cluster_config
          vault = Legion::Settings[:crypt][:vault]
          @cluster_name ? vault[:clusters].fetch(@cluster_name) : vault
        end

        def auth
          @auth ||= case cluster_config[:auth_method]&.to_s
                    when 'kerberos' then Legion::Crypt::Vault::Auth::Kerberos.new(cluster_name: @cluster_name)
                    when 'ldap'     then Legion::Crypt::Vault::Auth::LDAP.new(cluster_name: @cluster_name)
                    when 'jwt'      then Legion::Crypt::Vault::Auth::JWT.new(cluster_name: @cluster_name)
                    else
                      raise ArgumentError, "unsupported Vault auth_method: #{cluster_config[:auth_method].inspect}"
                    end
        end

        def authenticate
          auth.authenticate(client: @client)
          publish
        rescue Legion::Crypt::Vault::Auth::AuthError, *FAILURES => e
          handle_exception(e, level: :warn, operation: 'crypt.vault_session.authenticate', cluster_name: @cluster_name)
          raise
        end

        # A cluster with a pre-configured token and no auth method adopts it for renewal.
        def adopt_config_token
          token = cluster_config[:token]
          return if token.nil?

          @current_token = token
          @client.token = token
          @lease_duration = cluster_config[:lease_duration].to_f
          @renewable = cluster_config[:renewable] == true
          expires = cluster_config[:expires_at]
          @expires_at = expires.is_a?(String) ? Time.parse(expires) : expires
          Legion::Crypt.publish_vault_grant(cluster_name: @cluster_name, client: @client,
                                            grant: { token: token, lease_duration: cluster_config[:lease_duration],
                                                      renewable: @renewable },
                                            auth_method: 'token')
        end

        # Publishes the current auth grant to the cluster config + client; returns the new expires_at.
        def publish(current_token: @current_token)
          expires_at = Legion::Crypt.publish_vault_grant(cluster_name: @cluster_name, client: @client,
                                                         grant: grant_hash, auth_method: @auth_method,
                                                         current_token: current_token)
          @current_token = @auth.grant.client_token
          @lease_duration = @auth.grant.lease_duration.to_f
          @renewable = @auth.grant.renewable?
          @rejected = false
          @backoff = INITIAL_BACKOFF
          expires_at
        end

        def grant_hash
          g = @auth.grant
          { token: g.client_token, lease_duration: g.lease_duration, renewable: g.renewable?,
            policies: g.policies, metadata: g.metadata }
        end

        # Called while the caller already holds @state_mutex (start/login); do not re-acquire it.
        def start_maintenance
          if @lease_defs && !@lease_defs.empty? && @current_token
            @leases ||= Legion::Crypt::Vault::Leases.new(client: @client)
            @leases.start(definitions: @lease_defs)
            @leases.start_renewal_thread
          end
          return if @stop || @thread&.alive? || @current_token.nil?

          @thread = Thread.new { maintenance_loop }
          @thread.name = "vault-session-#{label}"
        end

        def request_stop
          @state_mutex.synchronize do
            @stop = true
            @wake.broadcast
          end
          @leases&.request_stop
          nil
        end

        def maintenance_loop
          return unless @expires_at

          wait(renewal_delay)
          while grant_active
            case maintain_token
            when :renewed
              @backoff = INITIAL_BACKOFF
              wait(renewal_delay)
            when :pending
              wait(renewal_delay)
            when :failed
              wait(retry_delay)
            else
              break
            end
          end
        end

        # One token maintenance step: renew at 75%, re-auth on expiry/rejection, else disconnect.
        def maintain_token
          return :finished if @expires_at.nil?

          return handle_expiry if @expires_at <= Time.now

          if @renewable
            outcome = renew_token
            return outcome if outcome != :rejected

            return handle_expiry
          end
          :pending
        end

        def handle_expiry
          return handoff if @auth&.can_reauth?

          disconnect_token(reason: 'expired')
          :finished
        end

        def renew_token
          deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + [@expires_at - Time.now, 0].max
          Legion::Crypt::Vault::Operation.with_timeout(deadline: deadline) { @auth.renew(client: @client) }
          publish
          log.info "Vault token renewed cluster=#{label} ttl=#{@lease_duration}s expires_at=#{@expires_at&.getutc&.iso8601}"
          :renewed
        rescue Legion::Crypt::Vault::GrantRejectedError => e
          handle_exception(e, level: :warn, operation: 'crypt.vault_session.renew', cluster_name: @cluster_name)
          :finished
        rescue *FAILURES => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.renew', cluster_name: @cluster_name)
          return :failed unless e.is_a?(Legion::Crypt::Vault::HTTPClientError) && !RETRYABLE_CODES.include?(e.code)

          @rejected = true
          :rejected
        end

        # The atomic re-auth handoff: re-auth, publish the new token, reissue leases under it, then
        # commit (revoke the old token) or roll back (restore the old token, keep the old leases).
        def handoff
          old_token = @current_token
          old_hash = @auth&.grant ? grant_hash : nil
          @disconnected = false
          begin
            @auth.reauth(client: @client)
          rescue *FAILURES, Legion::Crypt::Vault::Auth::AuthError => e
            handle_exception(e, level: :error, operation: 'crypt.vault_session.handoff_reauth', cluster_name: @cluster_name)
            return :failed
          end
          return :finished unless grant_active

          begin
            expires_at = publish(current_token: old_token)
          rescue Legion::Crypt::Vault::GrantRejectedError => e
            handle_exception(e, level: :warn, operation: 'crypt.vault_session.handoff_publish', cluster_name: @cluster_name)
            return :finished
          end
          recovered = @leases ? @leases.reissue_all(client: @client, active: method(:grant_active)) : true
          if recovered && grant_active
            @expires_at = expires_at
            revoke_token(old_token)
            log.info "Vault token re-authenticated cluster=#{label} ttl=#{@lease_duration}s"
            :renewed
          else
            restore(grant_hash: old_hash)
            log.error "Vault token re-auth incomplete cluster=#{label}; previous token retained"
            :failed
          end
        end

        # Rolls back to the pre-handoff grant after a failed reissue, keeping the old leases valid.
        def restore(grant_hash:)
          return if grant_hash.nil?

          Legion::Crypt.publish_vault_grant(cluster_name: @cluster_name, client: @client, grant: grant_hash,
                                            auth_method: @auth_method)
          @current_token = grant_hash[:token]
          @lease_duration = grant_hash[:lease_duration].to_f
          @renewable = grant_hash[:renewable] == true
        rescue Legion::Crypt::Vault::GrantRejectedError, *FAILURES => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.handoff_rollback', cluster_name: @cluster_name)
        end

        def disconnect_token(reason:)
          return if @disconnected

          @disconnected = true
          relogin_required = @auth.nil? || !@auth.can_reauth?
          Legion::Crypt.disconnect_vault_grant(cluster_name: @cluster_name, token: @current_token, relogin_required: relogin_required)
          log.error "Vault token #{reason} cluster=#{label}; #{relogin_required ? 'login required' : 're-authentication pending'}"
        end

        def revoke_token(token = @current_token)
          return if token.nil?

          Legion::Crypt.revoke_vault_token(client: @client, token: token)
        rescue *FAILURES => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.revoke', cluster_name: @cluster_name, outcome: 'incomplete')
        end

        def renewal_delay
          return RENEWAL_CHECK_INTERVAL if @expires_at.nil?

          remaining = @expires_at - Time.now
          delay = @renewable ? remaining - (@lease_duration * (1 - RENEWAL_RATIO)) : remaining
          [delay, MINIMUM_WAIT].max
        end

        def retry_delay
          delay = @backoff
          @backoff = [@backoff * 2, MAX_BACKOFF].min

          remaining = @expires_at ? @expires_at - Time.now : 0
          return delay if remaining <= 0

          floor = remaining / 2
          floor = MINIMUM_WAIT if floor < MINIMUM_WAIT
          [delay, floor].min
        end

        def wait(seconds)
          deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + seconds
          @state_mutex.synchronize do
            until @stop
              remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
              break unless remaining.positive?

              @wake.wait(@state_mutex, remaining)
            end
          end
        end
      end
    end
  end
end
