# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    class CertRotation
      include Legion::Logging::Helper

      DEFAULT_CHECK_INTERVAL = 43_200 # 12 hours

      attr_reader :check_interval, :current_cert, :issued_at

      def initialize(check_interval: DEFAULT_CHECK_INTERVAL)
        @check_interval = check_interval
        @current_cert   = nil
        @issued_at      = nil
        @running        = false
        @thread         = nil
        @mutex          = Mutex.new
      end

      def start
        return unless Legion::Crypt::Mtls.enabled?
        return if running?

        @running = true
        @thread  = Thread.new { rotation_loop }
        log.info('[mTLS] CertRotation started')
      end

      def stop
        @running = false
        begin
          @thread&.wakeup
        rescue ThreadError => e
          handle_exception(e, level: :debug, operation: 'crypt.cert_rotation.stop')
          nil
        end
        @thread&.join(2)
        if @thread&.alive?
          log.warn '[mTLS] CertRotation thread did not stop within timeout'
        else
          @thread = nil
        end
        log.info('[mTLS] CertRotation stopped')
      end

      def running?
        (@running && @thread&.alive?) || false
      end

      def rotate!
        node_name = node_common_name
        new_cert = Legion::Crypt::Mtls.issue_cert(common_name: node_name)
        @mutex.synchronize do
          @current_cert = new_cert
          @issued_at    = Time.now
        end
        log.info("[mTLS] Certificate rotated: serial=#{new_cert[:serial]} expiry=#{new_cert[:expiry]}")
        emit_rotated_event(new_cert)
        new_cert
      end

      def needs_renewal?
        current_cert = nil
        issued_at = nil
        @mutex.synchronize do
          current_cert = @current_cert
          issued_at = @issued_at
        end
        return false if current_cert.nil? || issued_at.nil?

        expiry = current_cert[:expiry]
        total  = expiry - issued_at
        return true if total <= 0

        remaining = expiry - Time.now
        fraction  = remaining / total
        fraction < renewal_window
      end

      private

      def rotation_loop
        rotate!
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cert_rotation.rotation_loop')
        log.error("[mTLS] Initial rotation failed: #{e.message}")
      ensure
        loop_check
      end

      def loop_check
        while @running
          interruptible_sleep(@check_interval)
          next unless @running && needs_renewal?

          begin
            rotate!
          rescue StandardError => e
            handle_exception(e, level: :error, operation: 'crypt.cert_rotation.loop_check')
            log.error("[mTLS] Rotation check failed: #{e.message}")
          end
        end
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.cert_rotation.loop_check')
        log.error("[mTLS] CertRotation loop error: #{e.message}")
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
        return 0.5 unless defined?(Legion::Settings)

        security = Legion::Settings[:security]
        return 0.5 if security.nil?

        mtls = security[:mtls] || security['mtls'] || {}
        mtls[:renewal_window] || mtls['renewal_window'] || 0.5
      rescue StandardError => e
        handle_exception(e, level: :debug, operation: 'crypt.cert_rotation.renewal_window')
        0.5
      end

      def node_common_name
        return 'legion.internal' unless defined?(Legion::Settings)

        name = Legion::Settings[:client]&.dig(:name) || Legion::Settings[:client]&.dig('name')
        name || 'legion.internal'
      rescue StandardError => e
        handle_exception(e, level: :debug, operation: 'crypt.cert_rotation.node_common_name')
        'legion.internal'
      end

      def emit_rotated_event(cert)
        return unless defined?(Legion::Events)

        Legion::Events.emit('cert.rotated', serial: cert[:serial], expiry: cert[:expiry])
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.cert_rotation.emit_rotated_event')
        log.warn("[mTLS] Event emit failed: #{e.message}")
      end
    end
  end
end
