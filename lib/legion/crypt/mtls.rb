# frozen_string_literal: true

require 'legion/logging/helper'
require 'socket'

module Legion
  module Crypt
    module Mtls
      DEFAULT_PKI_PATH = 'pki/issue/legion-internal'
      DEFAULT_TTL      = '24h'
      extend Legion::Logging::Helper

      class << self
        def enabled?
          security = safe_security_settings
          return false if security.nil?

          mtls = security[:mtls] || security['mtls']
          return false if mtls.nil?

          mtls[:enabled] || mtls['enabled'] || false
        end

        def pki_path
          security = safe_security_settings
          return DEFAULT_PKI_PATH if security.nil?

          mtls = security[:mtls] || security['mtls'] || {}
          mtls[:vault_pki_path] || mtls['vault_pki_path'] || DEFAULT_PKI_PATH
        end

        def issue_cert(common_name:, ttl: nil)
          resolved_ttl = ttl || cert_ttl_setting || DEFAULT_TTL
          log.info "[mTLS] certificate issue requested common_name=#{common_name} ttl=#{resolved_ttl}"

          response = ::Vault.logical.write(
            pki_path,
            common_name: common_name,
            ttl:         resolved_ttl,
            ip_sans:     local_ip,
            alt_names:   ''
          )

          raise "Vault PKI returned nil for #{pki_path} (common_name=#{common_name})" if response.nil?

          data = response.data

          {
            cert:     data[:certificate],
            key:      data[:private_key],
            ca_chain: Array(data[:ca_chain]),
            serial:   data[:serial_number],
            expiry:   Time.at(data[:expiration].to_i)
          }
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.mtls.issue_cert', common_name: common_name, ttl: resolved_ttl)
          raise
        end

        def local_ip
          Socket.ip_address_list.find { |a| a.ipv4? && !a.ipv4_loopback? }&.ip_address || '127.0.0.1'
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.mtls.local_ip')
          '127.0.0.1'
        end

        private

        def safe_security_settings
          return nil unless defined?(Legion::Settings)

          Legion::Settings[:security]
        rescue StandardError => e
          handle_exception(e, level: :debug, operation: 'crypt.mtls.safe_security_settings')
          nil
        end

        def cert_ttl_setting
          security = safe_security_settings
          return nil if security.nil?

          mtls = security[:mtls] || security['mtls'] || {}
          mtls[:cert_ttl] || mtls['cert_ttl']
        rescue StandardError => e
          handle_exception(e, level: :debug, operation: 'crypt.mtls.cert_ttl_setting')
          nil
        end
      end
    end
  end
end
