# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/vault_operation'

module Legion
  module Crypt
    class CertRotation
      include Legion::Logging::Helper

      DEFAULT_CHECK_INTERVAL = 43_200 # 12 hours
      MINIMUM_SLEEP = 0.01
      INITIAL_RETRY_DELAY = 1
      MAX_RETRY_DELAY = 60

      attr_reader :check_interval, :current_cert, :issued_at

      def initialize(check_interval: DEFAULT_CHECK_INTERVAL)
        unless check_interval.is_a?(Numeric) && check_interval.finite? && check_interval.positive?
          raise ArgumentError, 'Certificate check interval must be finite and positive'
        end

        @check_interval = check_interval
        @current_cert   = nil
        @issued_at      = nil
        @running        = false
        @thread         = nil
        @mutex          = Mutex.new
        @wake          = ConditionVariable.new
        @generation    = 0
        @retry_delay   = INITIAL_RETRY_DELAY
        @next_attempt  = 0
      end

      def start
        return unless Legion::Crypt::Mtls.enabled?

        @mutex.synchronize do
          return if @thread&.alive?

          @running = true
          @generation += 1
          generation = @generation
          @thread = Thread.new { rotation_loop(generation: generation) }
        end
        log.info('[mTLS] CertRotation started')
      end

      def stop(deadline: nil)
        thread = @mutex.synchronize do
          @running = false
          @generation += 1
          @wake.broadcast
          @thread
        end
        deadline ||= ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + Legion::Crypt::VaultOperation::SHUTDOWN_TIMEOUT
        Legion::Crypt::VaultOperation.with_timeout(deadline: deadline) { thread.join } if thread && thread != Thread.current
        @mutex.synchronize { @thread = nil if @thread.equal?(thread) && !thread&.alive? }
        log.info('[mTLS] CertRotation stopped')
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.cert_rotation.stop')
      end

      def running?
        @mutex.synchronize { (@running && @thread&.alive?) || false }
      end

      def rotate!(generation: nil)
        generation ||= @mutex.synchronize { @generation }
        new_cert = Legion::Crypt::VaultOperation.with_timeout { Legion::Crypt::Mtls.issue_cert(common_name: node_common_name) }
        issued_at = Time.now
        raise 'Vault PKI returned an expired certificate' unless new_cert[:expiry] > issued_at

        installed = @mutex.synchronize do
          next false unless generation == @generation

          @current_cert = new_cert
          @issued_at = issued_at
          @retry_delay = INITIAL_RETRY_DELAY
          @next_attempt = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + MINIMUM_SLEEP
          @wake.broadcast
          true
        end
        return unless installed

        log.info("[mTLS] Certificate rotated: serial=#{new_cert[:serial]} expiry=#{new_cert[:expiry]}")
        emit_rotated_event(new_cert)
        new_cert
      end

      def needs_renewal?
        @mutex.synchronize { renewal_delay <= 0 }
      end

      private

      def rotation_loop(generation:)
        loop do
          due = @mutex.synchronize do
            return unless @running && generation == @generation

            retry_wait = @next_attempt - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
            wait = [retry_wait, renewal_delay].max
            if wait.positive?
              @wake.wait(@mutex, [wait, @check_interval].min.clamp(MINIMUM_SLEEP, Float::INFINITY))
              false
            else
              true
            end
          end
          next unless due

          begin
            rotate!(generation: generation)
          rescue StandardError => e
            handle_exception(e, level: :error, operation: 'crypt.cert_rotation.rotation_loop')
            @mutex.synchronize do
              next unless @running && generation == @generation

              @next_attempt = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + @retry_delay
              @retry_delay = [@retry_delay * 2, MAX_RETRY_DELAY].min
            end
          end
        end
      end

      def renewal_delay
        return 0 unless @current_cert && @issued_at

        expiry = @current_cert[:expiry]
        lifetime = expiry - @issued_at
        expiry - Time.now - (lifetime * renewal_window)
      end

      def renewal_window
        return 0.5 unless defined?(Legion::Settings)

        security = Legion::Settings[:security]
        return 0.5 if security.nil?

        mtls = security[:mtls] || security['mtls'] || {}
        window = mtls[:renewal_window] || mtls['renewal_window'] || 0.5
        unless window.is_a?(Numeric) && window.finite? && window >= 0 && window < 1
          raise ArgumentError, 'Certificate renewal window must be finite and between zero and one (exclusive)'
        end

        window
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
