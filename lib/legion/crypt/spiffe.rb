# frozen_string_literal: true

require 'legion/logging/helper'
require 'uri'
require 'openssl'

module Legion
  module Crypt
    module Spiffe
      SPIFFE_SCHEME = 'spiffe'
      DEFAULT_SOCKET_PATH = '/tmp/spire-agent/public/api.sock'
      DEFAULT_TRUST_DOMAIN = 'legion.internal'
      SVID_RENEWAL_RATIO   = 0.5

      class Error < StandardError; end
      class InvalidSpiffeIdError < Error; end
      class WorkloadApiError < Error; end
      class SvidError < Error; end

      # Parsed representation of a SPIFFE ID.
      # A SPIFFE ID has the form: spiffe://<trust-domain>/<workload-path>
      SpiffeId = Struct.new(:trust_domain, :path) do
        def to_s
          "#{SPIFFE_SCHEME}://#{trust_domain}#{path}"
        end

        def ==(other)
          other.is_a?(SpiffeId) && trust_domain == other.trust_domain && path == other.path
        end
      end

      # Parsed X.509 SVID (SPIFFE Verifiable Identity Document).
      X509Svid = Struct.new(:spiffe_id, :cert_pem, :key_pem, :bundle_pem, :expiry, :source) do
        def expired?
          Time.now >= expiry
        end

        def valid?
          !cert_pem.nil? && !key_pem.nil? && !expired?
        end

        # Seconds remaining until expiry (negative if already expired).
        def ttl
          expiry - Time.now
        end
      end

      # Parsed JWT SVID.
      JwtSvid = Struct.new(:spiffe_id, :token, :audience, :expiry, :source) do
        def expired?
          Time.now >= expiry
        end

        def valid?
          !token.nil? && !expired?
        end
      end

      class << self
        include Legion::Logging::Helper

        # Parse a SPIFFE ID string into a SpiffeId struct.
        # Raises InvalidSpiffeIdError on malformed input.
        def parse_id(spiffe_id_string)
          raise InvalidSpiffeIdError, 'SPIFFE ID must be a non-empty string' if spiffe_id_string.nil? || spiffe_id_string.empty?

          uri = URI.parse(spiffe_id_string)
          validate_uri!(uri, spiffe_id_string)

          SpiffeId.new(
            trust_domain: uri.host,
            path:         uri.path.empty? ? '/' : uri.path
          )
        rescue URI::InvalidURIError => e
          handle_exception(e, level: :warn, operation: 'crypt.spiffe.parse_id', spiffe_id: spiffe_id_string)
          raise InvalidSpiffeIdError, "Invalid SPIFFE ID '#{spiffe_id_string}': #{e.message}"
        end

        def valid_id?(spiffe_id_string)
          parse_id(spiffe_id_string)
          true
        rescue InvalidSpiffeIdError => e
          handle_exception(e, level: :debug, operation: 'crypt.spiffe.valid_id', spiffe_id: spiffe_id_string)
          false
        end

        def enabled?
          security = safe_security_settings
          return false if security.nil?

          spiffe = security[:spiffe] || security['spiffe']
          return false if spiffe.nil?

          spiffe[:enabled] || spiffe['enabled'] || false
        end

        def socket_path
          security = safe_security_settings
          return DEFAULT_SOCKET_PATH if security.nil?

          spiffe = security[:spiffe] || security['spiffe'] || {}
          spiffe[:socket_path] || spiffe['socket_path'] || DEFAULT_SOCKET_PATH
        end

        def trust_domain
          security = safe_security_settings
          return DEFAULT_TRUST_DOMAIN if security.nil?

          spiffe = security[:spiffe] || security['spiffe'] || {}
          spiffe[:trust_domain] || spiffe['trust_domain'] || DEFAULT_TRUST_DOMAIN
        end

        def workload_id
          security = safe_security_settings
          return nil if security.nil?

          spiffe = security[:spiffe] || security['spiffe'] || {}
          spiffe[:workload_id] || spiffe['workload_id']
        end

        def allow_x509_fallback?
          security = safe_security_settings
          return false if security.nil?

          spiffe = security[:spiffe] || security['spiffe'] || {}
          spiffe[:allow_x509_fallback] || spiffe['allow_x509_fallback'] || false
        end

        private

        def validate_uri!(uri, raw)
          unless uri.scheme == SPIFFE_SCHEME
            raise InvalidSpiffeIdError,
                  "SPIFFE ID must use 'spiffe://' scheme, got '#{uri.scheme}://'"
          end
          raise InvalidSpiffeIdError, "SPIFFE ID missing trust domain in '#{raw}'" if uri.host.nil? || uri.host.empty?
          return unless uri.userinfo || uri.port || (uri.query && !uri.query.empty?) || (uri.fragment && !uri.fragment.empty?)

          raise InvalidSpiffeIdError, "SPIFFE ID must not contain userinfo, port, query, or fragment in '#{raw}'"
        end

        def safe_security_settings
          return nil unless defined?(Legion::Settings)

          Legion::Settings[:security]
        rescue StandardError => e
          handle_exception(e, level: :debug, operation: 'crypt.spiffe.safe_security_settings')
          nil
        end
      end
    end
  end
end
