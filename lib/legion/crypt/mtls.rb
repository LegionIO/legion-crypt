# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/settings'
require 'socket'

module Legion
  module Crypt
    module Mtls
      DEFAULT_PKI_PATH = 'pki/issue/legion-internal'
      DEFAULT_TTL = '24h'
      extend Legion::Logging::Helper

      class << self
        def enabled?
          Legion::Settings.dig(:security, :mtls, :enabled) == true
        end

        def pki_path
          path = Legion::Settings.dig(:security, :mtls, :vault_pki_path)
          path.nil? ? DEFAULT_PKI_PATH : path
        end

        def issue_cert(common_name:, ttl: nil)
          configured_ttl = Legion::Settings.dig(:security, :mtls, :cert_ttl)
          resolved_ttl = ttl.nil? ? configured_ttl : ttl
          resolved_ttl = DEFAULT_TTL if resolved_ttl.nil?
          log.info "[mTLS] certificate issue requested common_name=#{common_name} ttl=#{resolved_ttl}"

          response = Legion::Crypt.vault_client.logical.write(
            path: pki_path,
            data: { common_name: common_name, ttl: resolved_ttl, ip_sans: local_ip, alt_names: '' }
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
      end
    end
  end
end
