# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    module Spiffe
      # Background thread that keeps the current X.509 SVID fresh.
      #
      # Mirrors the pattern used by CertRotation (mTLS) but targets the
      # SPIFFE Workload API instead of Vault PKI.  The check interval
      # defaults to 60 seconds; renewal fires when the SVID is past 50%
      # of its lifetime (configurable via security.spiffe.renewal_window).
      class SvidRotation
        include Legion::Logging::Helper

        DEFAULT_CHECK_INTERVAL = 60

        attr_reader :check_interval, :current_svid

        def initialize(check_interval: DEFAULT_CHECK_INTERVAL, client: nil)
          @check_interval = check_interval
          @client         = client || WorkloadApiClient.new
          @current_svid   = nil
          @issued_at      = nil
          @running        = false
          @thread         = nil
          @mutex          = Mutex.new
        end

        def start
          return unless Legion::Crypt::Spiffe.enabled?
          return if running?

          @running = true
          @thread  = Thread.new { rotation_loop }
          @thread.name = 'spiffe-svid-rotation'
          log.info '[SPIFFE] SvidRotation started'
        end

        def stop
          @running = false
          begin
            @thread&.wakeup
          rescue ThreadError => e
            handle_exception(e, level: :debug, operation: 'crypt.spiffe.svid_rotation.stop')
            nil
          end
          @thread&.join(3)
          if @thread&.alive?
            log.warn '[SPIFFE] SvidRotation thread did not stop within timeout'
          else
            @thread = nil
          end
          log.info '[SPIFFE] SvidRotation stopped'
        end

        def running?
          (@running && @thread&.alive?) || false
        end

        def rotate!
          svid = @client.fetch_x509_svid
          @mutex.synchronize do
            @current_svid = svid
            @issued_at    = Time.now
          end
          log.info("[SPIFFE] SVID rotated: id=#{svid.spiffe_id} expiry=#{svid.expiry}")
          svid
        end

        def needs_renewal?
          svid      = nil
          issued_at = nil
          @mutex.synchronize do
            svid      = @current_svid
            issued_at = @issued_at
          end

          return true if svid.nil? || issued_at.nil?
          return true if svid.expired?

          total = svid.expiry - issued_at
          return true if total <= 0

          remaining = svid.expiry - Time.now
          fraction  = remaining / total
          fraction < renewal_window
        end

        private

        def rotation_loop
          begin
            rotate!
          rescue StandardError => e
            handle_exception(e, level: :error, operation: 'crypt.spiffe.svid_rotation.rotation_loop')
            log.error("[SPIFFE] Initial SVID fetch failed: #{e.message}")
          end
          loop_check
        end

        def loop_check
          while @running
            interruptible_sleep(@check_interval)
            next unless @running && needs_renewal?

            begin
              log.info('[SPIFFE] SVID renewal window reached, rotating current SVID')
              rotate!
            rescue StandardError => e
              handle_exception(e, level: :error, operation: 'crypt.spiffe.svid_rotation.loop_check')
              log.error("[SPIFFE] SVID rotation failed: #{e.message}")
            end
          end
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.spiffe.svid_rotation.loop_check')
          log.error("[SPIFFE] SvidRotation loop error: #{e.message}")
          retry if @running
        end

        def interruptible_sleep(seconds)
          deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + seconds
          loop do
            remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
            break if remaining <= 0 || !@running

            sleep([remaining, 1.0].min)
          end
        end

        def renewal_window
          return SVID_RENEWAL_RATIO unless defined?(Legion::Settings)

          security = Legion::Settings[:security]
          return SVID_RENEWAL_RATIO if security.nil?

          spiffe = security[:spiffe] || security['spiffe'] || {}
          spiffe[:renewal_window] || spiffe['renewal_window'] || SVID_RENEWAL_RATIO
        rescue StandardError => e
          handle_exception(e, level: :debug, operation: 'crypt.spiffe.svid_rotation.renewal_window')
          SVID_RENEWAL_RATIO
        end
      end
    end
  end
end
