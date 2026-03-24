# frozen_string_literal: true

module Legion
  module Crypt
    class CertRotation
      DEFAULT_CHECK_INTERVAL = 43_200 # 12 hours

      attr_reader :check_interval, :current_cert, :issued_at

      def initialize(check_interval: DEFAULT_CHECK_INTERVAL)
        @check_interval = check_interval
        @current_cert   = nil
        @issued_at      = nil
        @running        = false
        @thread         = nil
      end

      def start
        return unless Legion::Crypt::Mtls.enabled?
        return if running?

        @running = true
        @thread  = Thread.new { rotation_loop }
        log_info('[mTLS] CertRotation started')
      end

      def stop
        @running = false
        if @thread&.alive?
          @thread.kill
          @thread.join(2)
        end
        @thread = nil
        log_debug('[mTLS] CertRotation stopped')
      end

      def running?
        @running && @thread&.alive? || false
      end

      def rotate!
        node_name = node_common_name
        new_cert = Legion::Crypt::Mtls.issue_cert(common_name: node_name)
        @current_cert = new_cert
        @issued_at    = Time.now
        log_info("[mTLS] Certificate rotated: serial=#{new_cert[:serial]} expiry=#{new_cert[:expiry]}")
        emit_rotated_event(new_cert)
        new_cert
      end

      def needs_renewal?
        return false if @current_cert.nil? || @issued_at.nil?

        expiry = @current_cert[:expiry]
        total  = expiry - @issued_at
        return true if total <= 0

        remaining = expiry - Time.now
        fraction  = remaining / total
        fraction < renewal_window
      end

      private

      def rotation_loop
        rotate!
      rescue StandardError => e
        log_warn("[mTLS] Initial rotation failed: #{e.message}")
      ensure
        loop_check
      end

      def loop_check
        while @running
          sleep(@check_interval)
          next unless @running && needs_renewal?

          begin
            rotate!
          rescue StandardError => e
            log_warn("[mTLS] Rotation check failed: #{e.message}")
          end
        end
      rescue StandardError => e
        log_warn("[mTLS] CertRotation loop error: #{e.message}")
        retry if @running
      end

      def renewal_window
        return 0.5 unless defined?(Legion::Settings)

        security = Legion::Settings[:security]
        return 0.5 if security.nil?

        mtls = security[:mtls] || security['mtls'] || {}
        mtls[:renewal_window] || mtls['renewal_window'] || 0.5
      rescue StandardError
        0.5
      end

      def node_common_name
        return 'legion.internal' unless defined?(Legion::Settings)

        name = Legion::Settings[:client]&.dig(:name) || Legion::Settings[:client]&.dig('name')
        name || 'legion.internal'
      rescue StandardError
        'legion.internal'
      end

      def emit_rotated_event(cert)
        return unless defined?(Legion::Events)

        Legion::Events.emit('cert.rotated', serial: cert[:serial], expiry: cert[:expiry])
      rescue StandardError => e
        log_debug("[mTLS] Event emit failed: #{e.message}")
      end

      def log_info(msg)
        if defined?(Legion::Logging)
          Legion::Logging.info(msg)
        else
          $stdout.puts(msg)
        end
      end

      def log_debug(msg)
        if defined?(Legion::Logging)
          Legion::Logging.debug(msg)
        else
          $stdout.puts("[DEBUG] #{msg}")
        end
      end

      def log_warn(msg)
        if defined?(Legion::Logging)
          Legion::Logging.warn(msg)
        else
          warn("[WARN] #{msg}")
        end
      end
    end
  end
end
