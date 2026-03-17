# frozen_string_literal: true

require 'openssl'

module Legion
  module Crypt
    module TLS
      DEFAULT_CERT_DIR = '/etc/legion/tls'

      class << self
        def enabled?
          settings_dig(:enabled) == true
        end

        def ssl_context(role: :client) # rubocop:disable Lint/UnusedMethodArgument
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
          ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER

          ctx.cert = OpenSSL::X509::Certificate.new(File.read(cert_path)) if cert_path && File.exist?(cert_path)
          ctx.key = OpenSSL::PKey.read(File.read(key_path)) if key_path && File.exist?(key_path)
          ctx.ca_file = ca_path if ca_path && File.exist?(ca_path)

          ctx
        end

        def bunny_options
          return {} unless enabled?

          {
            tls:                 true,
            tls_cert:            cert_path,
            tls_key:             key_path,
            tls_ca_certificates: [ca_path].compact,
            verify_peer:         true
          }
        end

        def sequel_options
          return {} unless enabled?

          {
            sslmode:     'verify-full',
            sslcert:     cert_path,
            sslkey:      key_path,
            sslrootcert: ca_path
          }
        end

        def cert_path
          settings_dig(:cert_path) || File.join(DEFAULT_CERT_DIR, 'legion.crt')
        end

        def key_path
          settings_dig(:key_path) || File.join(DEFAULT_CERT_DIR, 'legion.key')
        end

        def ca_path
          settings_dig(:ca_path) || File.join(DEFAULT_CERT_DIR, 'ca-bundle.crt')
        end

        private

        def settings_dig(*keys)
          return nil unless defined?(Legion::Settings)

          result = Legion::Settings[:crypt]
          [:tls, *keys].each do |key|
            return nil unless result.is_a?(Hash)

            result = result[key]
          end
          result
        rescue StandardError
          nil
        end
      end
    end
  end
end
