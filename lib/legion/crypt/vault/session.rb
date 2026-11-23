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
      # Owns one cluster's token + leases lifecycle. Holds the current grant (the login auth
      # response — the source of truth for the token's identity and lifetime) directly, so renewal
      # and revocation work for both minted (auth-method) and adopted (static/config) tokens.
      # Network I/O runs outside @state_mutex; only state transitions hold it briefly, so a
      # concurrent request_stop is never blocked behind a network call. One instance per cluster.
      class Session
        include Legion::Logging::Helper

        RENEWAL_RATIO          = 0.75
        INITIAL_BACKOFF        = 30
        MAX_BACKOFF            = 600
        MINIMUM_WAIT           = 0.01
        RENEWAL_CHECK_INTERVAL = 5
        RETRYABLE_CODES        = [408, 429].freeze
        STANDBY_CODES          = [429, 472, 473].freeze # standby, DR secondary, performance standby
        FAILURES               = [IOError, SystemCallError, Timeout::Error, Faraday::Error,
                                  Legion::Crypt::Vault::HTTPError].freeze

        attr_reader :cluster_name, :client

        def initialize(cluster_name:, client:, leases: nil, lease_defs: nil, **)
          @cluster_name = cluster_name
          @client = client
          @leases = leases
          @lease_defs = lease_defs
          @auth = nil
          @auth_method = nil
          @grant = nil
          @current_token = nil
          @lease_duration = 0
          @renewable = false
          @expires_at = nil
          @rejected = false
          @disconnected = false
          @backoff = INITIAL_BACKOFF
          @minted = false
          @stop = false
          @started = false
          @thread = nil
          @state_mutex = Mutex.new
          @transition_mutex = Mutex.new
          @wake = ConditionVariable.new
        end

        # Kerberos and static-token clusters authenticate at start; LDAP/JWT wait for an explicit login.
        def start(**)
          return false unless begin_lifecycle

          @auth_method = cluster_config[:auth_method]&.to_s
          return false if (@auth_method == 'kerberos') && !authenticate

          adopt_config_token if @auth_method.nil? || @auth_method.empty?
          start_maintenance
          true
        rescue Legion::Crypt::Vault::Auth::AuthError, Legion::Crypt::Vault::GrantRejectedError, *FAILURES => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.start', cluster_name: @cluster_name)
          false
        end

        # Explicit LDAP/JWT login. Returns the grant Hash (the pre-refactor ldap_login contract);
        # a failed login raises to the caller, which owns reporting it.
        def login(**creds)
          @transition_mutex.synchronize do
            raise Legion::Crypt::Vault::GrantRejectedError, 'Vault session stopped during login' if stopped?

            grant = auth.authenticate(client: @client, **creds)
            previous, expires_at, minted = @state_mutex.synchronize { [@grant, @expires_at, @minted] }
            if previous
              installed = replace_grant(candidate: grant, old_grant: previous, old_expires: expires_at, old_minted: minted)
              raise Legion::Crypt::Vault::GrantRejectedError, 'Vault login handoff failed' unless installed
            else
              raise Legion::Crypt::Vault::GrantRejectedError, 'Vault session stopped during login' unless commit_minted_grant(grant: grant)
            end

            start_maintenance
            grant_hash
          end
        end

        # Stops the maintenance thread, shuts down the leases, and then revokes a MINTED (auth-method)
        # token. An adopted static/config token is never revoked — it belongs to the operator.
        # Returns whether the leases and the token were actually cleaned up in Vault.
        def stop(deadline:, **)
          request_stop
          thread = @state_mutex.synchronize { @thread }
          if thread && thread != Thread.current
            remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
            thread.join(remaining) if remaining.positive?
          end
          leases_released = @leases.nil? || @leases.shutdown(deadline: deadline)
          token_released = !@state_mutex.synchronize { @minted && revocable_locked? } || revoke_token
          if leases_released && token_released
            log.info "Vault session stopped cluster=#{label}"
          else
            log.error "Vault session stopped with incomplete cleanup cluster=#{label} leases=#{leases_released} token=#{token_released}"
          end
          leases_released && token_released
        end

        # Signals the maintenance thread to stop. Public so Legion::Crypt.shutdown can request an
        # early stop without racing the lifecycle lock across a network call.
        def request_stop
          @state_mutex.synchronize do
            @stop = true
            @wake.broadcast
          end
          @leases&.request_stop
          nil
        end

        def running?
          @state_mutex.synchronize { @thread&.alive? == true }
        end

        def revocable?
          @state_mutex.synchronize { revocable_locked? }
        end

        def principal
          @state_mutex.synchronize { @grant&.metadata&.dig(:username) }
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

        def stopped?
          @state_mutex.synchronize { @stop }
        end

        def begin_lifecycle
          @state_mutex.synchronize do
            return false if @stop || @started

            @started = true
            true
          end
        end

        def revocable_locked?
          !@rejected && (@expires_at.nil? || @expires_at > Time.now)
        end

        # Network auth runs outside the mutex; the grant commit is a brief mutex hold.
        def authenticate
          @transition_mutex.synchronize do
            grant = auth.authenticate(client: @client)
            commit_minted_grant(grant: grant)
          end
        end

        # Adopts a pre-configured (static) token once Vault answers a health check. It is non-minted,
        # so it is never revoked on stop, and it is renewed only if its configuration says renewable.
        def adopt_config_token
          token = cluster_config[:token]
          return if token.nil?

          @auth_method = 'token'
          return Legion::Crypt.disconnect_vault_grant(cluster_name: @cluster_name, token: token, relogin_required: false) unless cluster_healthy?

          grant = Legion::Crypt::Vault::Client::Auth.new(data: { client_token:   token,
                                                                 lease_duration: cluster_config[:lease_duration],
                                                                 renewable:      cluster_config[:renewable] })
          commit_grant(grant: grant, minted: false)
        end

        # Brief mutex hold: publishes the grant before installing it as current.
        # previous_token guards against a concurrent token change; nil bypasses it (a first auth or a
        # rollback restore). Returns the current token, or nil when the session is stopping.
        def commit_grant(grant:, minted:, previous_token: nil, issued_at: Time.now)
          @state_mutex.synchronize do
            return if @stop

            token = grant.client_token
            lease_duration = grant.lease_duration.to_f
            renewable = grant.renewable?
            expires_at = Legion::Crypt.publish_vault_grant(cluster_name: @cluster_name, client: @client,
                                                           grant: grant_hash(grant: grant), auth_method: @auth_method,
                                                           issued_at: issued_at, current_token: previous_token)
            @grant = grant
            @minted = minted
            @disconnected = false
            @rejected = false
            @backoff = INITIAL_BACKOFF
            @current_token = token
            @lease_duration = lease_duration
            @renewable = renewable
            @expires_at = expires_at
            @current_token
          end
        end

        def commit_minted_grant(grant:, previous_token: nil)
          committed = commit_grant(grant: grant, minted: true, previous_token: previous_token)
          committed
        ensure
          revoke_uninstalled_grant(grant) if grant && !committed
        end

        def revoke_uninstalled_grant(grant)
          token = grant.client_token
          return if @state_mutex.synchronize { @current_token == token }

          revoke_token(token: token)
        end

        def grant_hash(grant: @grant)
          g = grant
          { token: g.client_token, lease_duration: g.lease_duration, renewable: g.renewable?,
            policies: g.policies, metadata: g.metadata }
        end

        def cluster_healthy?
          Legion::Crypt::Vault::Operation.with_timeout { @client.sys.health_status.initialized? }
        rescue Legion::Crypt::Vault::HTTPError => e
          return true if STANDBY_CODES.include?(e.code)

          handle_exception(e, level: :error, operation: 'crypt.vault_session.health', cluster_name: @cluster_name)
          false
        end

        def start_maintenance
          return if stopped? || @state_mutex.synchronize { @current_token.nil? }

          if @leases
            @leases.start(definitions: @lease_defs, client: @client)
            @leases.start_renewal_thread
          end
          @state_mutex.synchronize do
            return if @stop || @thread&.alive?

            @thread = Thread.new { maintenance_loop }
            @thread.name = "vault-session-#{label}"
          end
        end

        def maintenance_loop
          return unless @state_mutex.synchronize { @expires_at }

          wait(renewal_delay)
          while grant_active
            case maintain_token
            when :renewed
              @state_mutex.synchronize { @backoff = INITIAL_BACKOFF }
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

        # Renewal is attempted only when Vault's last auth response said the token is renewable.
        # A token that cannot be renewed is replaced by re-authentication (Kerberos) ahead of its
        # expiry, or left to expire and disconnect (LDAP/JWT/static).
        def maintain_token
          expired, renewable = @state_mutex.synchronize do
            return :finished if @expires_at.nil?

            [@expires_at <= Time.now, @renewable]
          end
          if renewable && !expired
            outcome = renew_token
            return outcome unless outcome == :rejected
          elsif !expired && !reauthable?
            return :pending
          end
          return handoff if reauthable?

          disconnect_token(reason: 'expired')
          :finished
        end

        def reauthable?
          @auth&.can_reauth? == true
        end

        # Renewal uses the client directly so it works for both minted and adopted (static) tokens.
        def renew_token
          @transition_mutex.synchronize do
            deadline, minted, previous_token = @state_mutex.synchronize do
              return :pending unless @renewable && @expires_at && @expires_at > Time.now

              remaining = @expires_at ? @expires_at - Time.now : 0
              [::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + [remaining, 0].max, @minted, @current_token]
            end
            renewed = Legion::Crypt::Vault::Operation.with_timeout(deadline: deadline) { @client.auth_token.renew_self }&.auth
            raise Legion::Crypt::Vault::Auth::AuthError, 'Vault token renewal returned no auth data' if renewed.nil?

            commit_grant(grant: renewed, minted: minted, previous_token: previous_token)
            log.info "Vault token renewed cluster=#{label} ttl=#{@state_mutex.synchronize { @lease_duration }}s"
            :renewed
          end
        rescue Legion::Crypt::Vault::GrantRejectedError => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.renew', cluster_name: @cluster_name)
          :finished
        rescue *FAILURES, Legion::Crypt::Vault::Auth::AuthError => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.renew', cluster_name: @cluster_name)
          rejected = e.is_a?(Legion::Crypt::Vault::HTTPClientError) && !RETRYABLE_CODES.include?(e.code)
          @state_mutex.synchronize { @rejected = true } if rejected
          rejected ? :rejected : :failed
        end

        # Re-authenticate, publish the candidate, reissue leases, then revoke the old token.
        # On failure, restore the previous grant before revoking the candidate.
        def handoff
          @transition_mutex.synchronize do
            old_grant, old_expires, old_minted = @state_mutex.synchronize { [@grant, @expires_at, @minted] }
            candidate = @auth.reauth(client: @client)
            unless grant_active
              revoke_uninstalled_grant(candidate)
              return :finished
            end

            if replace_grant(candidate: candidate, old_grant: old_grant, old_expires: old_expires, old_minted: old_minted)
              log.info "Vault token re-authenticated cluster=#{label} ttl=#{candidate.lease_duration}s"
              :renewed
            else
              :failed
            end
          end
        rescue Legion::Crypt::Vault::GrantRejectedError => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.handoff', cluster_name: @cluster_name)
          :finished
        rescue *FAILURES, Legion::Crypt::Vault::Auth::AuthError => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.handoff', cluster_name: @cluster_name)
          :failed
        end

        def replace_grant(candidate:, old_grant:, old_expires:, old_minted:)
          committed = commit_minted_grant(grant: candidate, previous_token: old_grant.client_token)
          raise Legion::Crypt::Vault::GrantRejectedError, 'Vault session stopped during grant handoff' unless committed

          recovered = begin
            grant_active && (@leases.nil? || @leases.reissue_all(client: @client, active: method(:grant_active)))
          rescue StandardError
            restore_previous_grant(candidate: candidate, old_grant: old_grant, old_expires: old_expires, old_minted: old_minted)
            raise
          end
          if recovered && grant_active
            revoke_token(token: old_grant.client_token) if old_minted
            return true
          end

          restore_previous_grant(candidate: candidate, old_grant: old_grant, old_expires: old_expires, old_minted: old_minted)
          false
        end

        def restore_previous_grant(candidate:, old_grant:, old_expires:, old_minted:)
          restored = commit_grant(grant: old_grant, minted: old_minted, previous_token: candidate.client_token,
                                  issued_at: old_expires - old_grant.lease_duration.to_f)
          raise Legion::Crypt::Vault::GrantRejectedError, 'Vault session stopped during grant restore' unless restored

          revoke_token(token: candidate.client_token)
          log.error "Vault token handoff incomplete cluster=#{label}; previous token retained"
        rescue Legion::Crypt::Vault::GrantRejectedError
          Legion::Crypt.disconnect_vault_grant(cluster_name: @cluster_name, token: candidate.client_token,
                                               relogin_required: true)
          @state_mutex.synchronize { @disconnected = true if @current_token == candidate.client_token }
          revoke_token(token: candidate.client_token)
          raise
        end

        def disconnect_token(reason:)
          @state_mutex.synchronize do
            return if @disconnected

            @disconnected = true
            Legion::Crypt.disconnect_vault_grant(cluster_name: @cluster_name, token: @current_token,
                                                 relogin_required: !reauthable?)
            log.error "Vault token #{reason} cluster=#{label}; #{reauthable? ? 're-authentication pending' : 'login required'}"
          end
        end

        # Returns whether the token is gone from Vault; a failed revocation is reported, not hidden.
        def revoke_token(token: @state_mutex.synchronize { @current_token })
          return true if token.nil?

          Legion::Crypt.revoke_vault_token(client: @client, token: token)
          true
        rescue *FAILURES => e
          handle_exception(e, level: :error, operation: 'crypt.vault_session.revoke', cluster_name: @cluster_name,
                             outcome: 'incomplete')
          false
        end

        def renewal_delay
          @state_mutex.synchronize do
            return RENEWAL_CHECK_INTERVAL if @expires_at.nil?

            remaining = @expires_at - Time.now
            delay = @renewable || reauthable? ? remaining - (@lease_duration * (1 - RENEWAL_RATIO)) : remaining
            [delay, MINIMUM_WAIT].max
          end
        end

        def retry_delay
          @state_mutex.synchronize do
            delay = @backoff
            @backoff = [@backoff * 2, MAX_BACKOFF].min

            remaining = @expires_at ? @expires_at - Time.now : 0
            return delay if remaining <= 0

            floor = remaining / 2
            floor = MINIMUM_WAIT if floor < MINIMUM_WAIT
            [delay, floor].min
          end
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
