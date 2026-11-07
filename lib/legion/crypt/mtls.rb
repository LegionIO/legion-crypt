# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/settings'
require 'socket'

module Legion
  module Crypt
    module Mtls
      extend Legion::Logging::Helper

      class << self
        def enabled?
          Legion::Settings[:crypt][:mtls][:enabled] == true
        end

        def issue_cert(common_name:, alt_names: '', ttl: nil, **)
          pki_path = Legion::Settings[:crypt][:mtls][:vault_pki_path]
          resolved_ttl = ttl.nil? ? Legion::Settings[:crypt][:mtls][:cert_ttl] : ttl
          log.info "[mTLS] certificate issue requested common_name=#{common_name} ttl=#{resolved_ttl}"

          response = Legion::Crypt.vault_client.logical.write(
            path: pki_path,
            data: { common_name: common_name, ttl: resolved_ttl, ip_sans: local_ip, alt_names: alt_names }
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
