# frozen_string_literal: true

require 'jwt'
require 'securerandom'
require 'legion/logging/helper'
require 'legion/crypt/jwks_client'

module Legion
  module Crypt
    module JWT
      class Error < StandardError; end
      class ExpiredTokenError < Error; end
      class InvalidTokenError < Error; end
      class DecodeError < Error; end

      SUPPORTED_ALGORITHMS = %w[HS256 RS256].freeze

      extend Legion::Logging::Helper

      def self.issue(payload, signing_key:, algorithm: 'HS256', ttl: 3600, issuer: 'legion')
        validate_algorithm!(algorithm)

        now = Time.now.to_i
        claims = sanitize_payload(payload).merge(
          iss: issuer,
          iat: now,
          exp: now + ttl,
          jti: SecureRandom.uuid
        )

        token = ::JWT.encode(claims, signing_key, algorithm)
        log.info "JWT issued: sub=#{claims[:sub]}, exp=#{Time.at(claims[:exp]).utc.iso8601}, alg=#{algorithm}"
        token
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.jwt.issue', algorithm: algorithm, issuer: issuer)
        raise
      end

      def self.issue_identity_token(signing_key:, extra_claims: {}, algorithm: 'HS256', ttl: 3600)
        unless defined?(Legion::Identity::Process) && Legion::Identity::Process.resolved?
          raise ArgumentError,
                'Identity::Process not resolved'
        end

        identity = Legion::Identity::Process.identity_hash
        identity_fields = {
          sub:            identity[:canonical_name],
          principal_id:   identity[:id],
          canonical_name: identity[:canonical_name],
          kind:           identity[:kind].to_s,
          mode:           identity[:mode].to_s,
          groups:         (identity[:groups] || [])[0, 50]
        }
        payload = extra_claims.merge(identity_fields)

        issue(payload, signing_key: signing_key, algorithm: algorithm, ttl: ttl)
      end

      def self.verify(token, verification_key:, **opts)
        algorithm = opts.fetch(:algorithm, 'HS256')
        verify_expiration = opts.fetch(:verify_expiration, true)
        verify_issuer = opts.fetch(:verify_issuer, true)
        issuer = opts.fetch(:issuer, 'legion')

        validate_algorithm!(algorithm)

        decode_opts = {
          algorithm:         algorithm,
          verify_expiration: verify_expiration,
          verify_iss:        verify_issuer
        }
        decode_opts[:iss] = issuer if verify_issuer

        payload, _header = ::JWT.decode(token, verification_key, true, decode_opts)
        result = symbolize_keys(payload)
        log.debug "JWT verify success: sub=#{result[:sub]}, jti=#{result[:jti]}"
        result
      rescue ::JWT::ExpiredSignature => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.verify.expired', algorithm: algorithm)
        log.warn 'JWT verify failed: token has expired'
        raise ExpiredTokenError, 'token has expired'
      rescue ::JWT::VerificationError, ::JWT::IncorrectAlgorithm => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.verify.signature', algorithm: algorithm)
        log.warn 'JWT verify failed: signature verification failed'
        raise InvalidTokenError, 'token signature verification failed'
      rescue ::JWT::DecodeError => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.verify.decode', algorithm: algorithm)
        log.warn "JWT verify failed: #{e.message}"
        raise DecodeError, "failed to decode token: #{e.message}"
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.jwt.verify', algorithm: algorithm)
        raise
      end

      def self.decode(token)
        payload, _header = ::JWT.decode(token, nil, false)
        symbolize_keys(payload)
      rescue ::JWT::DecodeError => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.decode')
        raise DecodeError, "failed to decode token: #{e.message}"
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.jwt.decode')
        raise
      end

      def self.verify_with_jwks(token, jwks_url:, **opts)
        header = decode_header(token)
        kid = header['kid']
        algorithm = header['alg'] || 'RS256'

        raise InvalidTokenError, 'token header missing kid' unless kid

        validate_algorithm!(algorithm)

        public_key = Legion::Crypt::JwksClient.find_key(jwks_url, kid)

        verify_expiration = opts.fetch(:verify_expiration, true)
        issuers = opts[:issuers]
        audience = opts[:audience]
        validate_external_requirements!(issuers: issuers, audience: audience)

        decode_opts = {
          algorithm:         algorithm,
          verify_expiration: verify_expiration,
          verify_iss:        true,
          iss:               issuers,
          verify_aud:        true,
          aud:               audience
        }

        payload, _header = ::JWT.decode(token, public_key, true, decode_opts)
        result = symbolize_keys(payload)
        log.info "JWT JWKS verify success: sub=#{result[:sub]}, kid=#{kid}"
        result
      rescue ::JWT::ExpiredSignature => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.verify_with_jwks.expired', jwks_url: jwks_url, kid: kid)
        log.warn "JWT JWKS verify failed: token has expired, kid=#{kid}"
        raise ExpiredTokenError, 'token has expired'
      rescue ::JWT::VerificationError, ::JWT::IncorrectAlgorithm => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.verify_with_jwks.signature', jwks_url: jwks_url, kid: kid)
        log.warn "JWT JWKS verify failed: signature verification failed, kid=#{kid}"
        raise InvalidTokenError, 'token signature verification failed'
      rescue ::JWT::InvalidIssuerError => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.verify_with_jwks.issuer', jwks_url: jwks_url, kid: kid)
        log.warn "JWT JWKS verify failed: issuer not allowed, kid=#{kid}"
        raise InvalidTokenError, 'token issuer not allowed'
      rescue ::JWT::InvalidAudError => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.verify_with_jwks.audience', jwks_url: jwks_url, kid: kid)
        log.warn "JWT JWKS verify failed: audience mismatch, kid=#{kid}"
        raise InvalidTokenError, 'token audience mismatch'
      rescue ::JWT::DecodeError => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.verify_with_jwks.decode', jwks_url: jwks_url, kid: kid)
        log.warn "JWT JWKS verify failed: #{e.message}, kid=#{kid}"
        raise DecodeError, "failed to decode token: #{e.message}"
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.jwt.verify_with_jwks', jwks_url: jwks_url, kid: kid)
        raise
      end

      def self.decode_header(token)
        parts = token.to_s.split('.')
        raise DecodeError, 'invalid token format' unless parts.size == 3

        header_json = Base64.urlsafe_decode64(parts[0])
        ::JSON.parse(header_json)
      rescue ::JSON::ParserError, ArgumentError => e
        handle_exception(e, level: :warn, operation: 'crypt.jwt.decode_header')
        raise DecodeError, "failed to decode token header: #{e.message}"
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.jwt.decode_header')
        raise
      end

      def self.validate_algorithm!(algorithm)
        return if SUPPORTED_ALGORITHMS.include?(algorithm)

        raise ArgumentError, "unsupported algorithm: #{algorithm}. Supported: #{SUPPORTED_ALGORITHMS.join(', ')}"
      end

      def self.symbolize_keys(hash)
        hash.transform_keys(&:to_sym)
      end

      def self.sanitize_payload(payload)
        payload.each_with_object({}) do |(key, value), sanitized|
          next if %w[iss iat exp jti].include?(key.to_s)

          sanitized[key] = value
        end
      end

      def self.validate_external_requirements!(issuers:, audience:)
        raise ArgumentError, 'issuers is required for JWKS verification' if blank_external_requirement?(issuers)
        raise ArgumentError, 'audience is required for JWKS verification' if blank_external_requirement?(audience)
      end

      def self.blank_external_requirement?(value)
        return true if value.nil?
        return true if value.respond_to?(:empty?) && value.empty?

        false
      end

      private_class_method :validate_algorithm!, :symbolize_keys, :decode_header, :sanitize_payload,
                           :validate_external_requirements!, :blank_external_requirement?
    end
  end
end
