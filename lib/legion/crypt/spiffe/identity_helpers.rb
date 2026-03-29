# frozen_string_literal: true

require 'openssl'
require 'base64'

module Legion
  module Crypt
    module Spiffe
      # Helpers for signing, verifying, and inspecting SPIFFE SVIDs.
      #
      # These methods work directly with X509Svid and JwtSvid structs
      # returned by WorkloadApiClient.  No external gem is required —
      # all operations use the Ruby stdlib OpenSSL bindings.
      module IdentityHelpers
        # Sign arbitrary data with the private key from an X.509 SVID.
        # Returns the signature as a Base64-encoded string.
        #
        # @param data [String] The bytes to sign (any encoding; treated as binary).
        # @param svid [X509Svid] An X509Svid whose key_pem is populated.
        # @return [String] Base64-encoded DER signature.
        def sign_with_svid(data, svid:)
          raise SvidError, 'Cannot sign: SVID is nil' if svid.nil?
          raise SvidError, "Cannot sign: SVID '#{svid.spiffe_id}' has expired" if svid.expired?
          raise SvidError, 'Cannot sign: SVID private key is missing' if svid.key_pem.nil?

          key       = OpenSSL::PKey.read(svid.key_pem)
          digest    = OpenSSL::Digest.new('SHA256')
          signature = key.sign(digest, data.b)
          Base64.strict_encode64(signature)
        end

        # Verify a Base64-encoded signature produced by sign_with_svid.
        #
        # @param data [String] Original data that was signed.
        # @param signature_b64 [String] Base64-encoded signature from sign_with_svid.
        # @param svid [X509Svid] The SVID whose public certificate is used for verification.
        # @return [Boolean] true if the signature is valid.
        def verify_svid_signature(data, signature_b64:, svid:)
          raise SvidError, 'Cannot verify: SVID is nil' if svid.nil?
          raise SvidError, "Cannot verify: SVID '#{svid.spiffe_id}' has expired" if svid.expired?
          raise SvidError, 'Cannot verify: SVID certificate is missing' if svid.cert_pem.nil?

          cert      = OpenSSL::X509::Certificate.new(svid.cert_pem)
          digest    = OpenSSL::Digest.new('SHA256')
          signature = Base64.strict_decode64(signature_b64)
          cert.public_key.verify(digest, signature, data.b)
        rescue OpenSSL::PKey::PKeyError, OpenSSL::X509::CertificateError, ArgumentError => e
          log_spiffe_warn("SVID signature verification error: #{e.message}")
          false
        end

        # Extract the SPIFFE ID embedded in an X.509 certificate's SAN URI extension.
        # Returns a SpiffeId struct or nil if none is found.
        #
        # @param cert_pem [String] PEM-encoded X.509 certificate.
        # @return [SpiffeId, nil]
        def extract_spiffe_id_from_cert(cert_pem)
          cert = OpenSSL::X509::Certificate.new(cert_pem)
          san  = cert.extensions.find { |e| e.oid == 'subjectAltName' }
          return nil unless san

          san.value.split(',').each do |entry|
            entry = entry.strip
            next unless entry.start_with?('URI:spiffe://')

            uri = entry.sub('URI:', '')
            return Legion::Crypt::Spiffe.parse_id(uri)
          rescue InvalidSpiffeIdError
            next
          end

          nil
        rescue OpenSSL::X509::CertificateError
          nil
        end

        # Validate that a certificate chain is trusted by the bundle embedded
        # in the given SVID.  Returns true if the leaf cert chains up to the
        # bundle CA, false otherwise.
        #
        # @param cert_pem [String] PEM-encoded leaf certificate to validate.
        # @param svid [X509Svid] SVID whose bundle_pem contains the trust anchor.
        # @return [Boolean]
        def trusted_cert?(cert_pem, svid:)
          raise SvidError, 'Cannot check trust: SVID is nil' if svid.nil?
          return false if svid.bundle_pem.nil?

          store = OpenSSL::X509::Store.new
          store.add_cert(OpenSSL::X509::Certificate.new(svid.bundle_pem))

          leaf = OpenSSL::X509::Certificate.new(cert_pem)
          store.verify(leaf)
        rescue OpenSSL::X509::CertificateError, OpenSSL::X509::StoreError
          false
        end

        # Return a hash of identity information extracted from an SVID.
        #
        # @param svid [X509Svid, JwtSvid] Any SVID type.
        # @return [Hash]
        def svid_identity(svid)
          return {} if svid.nil?

          base = {
            spiffe_id:     svid.spiffe_id.to_s,
            trust_domain:  svid.spiffe_id.trust_domain,
            workload_path: svid.spiffe_id.path,
            expiry:        svid.expiry,
            expired:       svid.expired?
          }

          case svid
          when X509Svid
            base.merge(type: :x509, ttl_seconds: svid.ttl.to_i)
          when JwtSvid
            base.merge(type: :jwt, audience: svid.audience)
          else
            base
          end
        end

        private

        def log_spiffe_warn(message)
          Legion::Logging.warn("[SPIFFE] #{message}") if defined?(Legion::Logging)
        end
      end
    end
  end
end
