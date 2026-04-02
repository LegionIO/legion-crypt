# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    module TLS
      TLS_PORTS = {
        5671   => 'amqp',
        6380   => 'redis',
        11_207 => 'memcached'
      }.freeze

      extend Legion::Logging::Helper

      class << self
        def resolve(tls_config, port: nil)
          config = symbolize_keys(migrate_legacy(tls_config || {}))

          enabled       = config[:enabled]
          auto_detected = false

          if enabled.nil? && port && TLS_PORTS.key?(port.to_i)
            enabled = true
            auto_detected = true
            log.warn("TLS auto-enabled for port #{port}")
          end

          enabled = false if enabled.nil?

          verify = normalize_verify(config[:verify])
          ca     = resolve_uri(config[:ca])
          cert   = resolve_uri(config[:cert])
          key    = resolve_uri(config[:key])

          if verify == :mutual && (cert.nil? || key.nil?)
            log.warn('TLS mutual requested but cert or key missing, downgrading to peer')
            verify = :peer
          end

          log.info "TLS resolved enabled=#{enabled} verify=#{verify} auto_detected=#{auto_detected}"

          {
            enabled:       enabled,
            verify:        verify,
            ca:            ca,
            cert:          cert,
            key:           key,
            auto_detected: auto_detected
          }
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.tls.resolve', port: port)
          raise
        end

        def migrate_legacy(config)
          config = symbolize_keys(config)
          return config unless config.key?(:use_tls) && !config.key?(:enabled)

          {
            enabled: config[:use_tls],
            verify:  config[:verify_peer] ? 'peer' : 'none',
            ca:      config[:ca_certs],
            cert:    config[:tls_cert],
            key:     config[:tls_key]
          }
        end

        private

        def symbolize_keys(hash)
          hash.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
        end

        def normalize_verify(value)
          case value.to_s
          when 'none'   then :none
          when 'mutual' then :mutual
          else :peer
          end
        end

        def resolve_uri(value)
          return nil if value.nil?

          if defined?(Legion::Settings::Resolver)
            Legion::Settings::Resolver.resolve_value(value)
          else
            value
          end
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.tls.resolve_uri')
          raise
        end
      end
    end
  end
end
