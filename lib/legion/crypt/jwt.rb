# frozen_string_literal: true

require 'jwt'
require 'securerandom'
require 'legion/crypt/jwks_client'

module Legion
  module Crypt
    module JWT
      class Error < StandardError; end
      class ExpiredTokenError < Error; end
      class InvalidTokenError < Error; end
      class DecodeError < Error; end

      SUPPORTED_ALGORITHMS = %w[HS256 RS256].freeze

      def self.issue(payload, signing_key:, algorithm: 'HS256', ttl: 3600, issuer: 'legion')
        validate_algorithm!(algorithm)

        now = Time.now.to_i
        claims = {
          iss: issuer,
          iat: now,
          exp: now + ttl,
          jti: SecureRandom.uuid
        }.merge(payload)

        token = ::JWT.encode(claims, signing_key, algorithm)
        Legion::Logging.info "JWT issued: sub=#{claims[:sub]}, exp=#{Time.at(claims[:exp]).utc.iso8601}, alg=#{algorithm}" if defined?(Legion::Logging)
        token
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
        Legion::Logging.debug "JWT verify success: sub=#{result[:sub]}, jti=#{result[:jti]}" if defined?(Legion::Logging)
        result
      rescue ::JWT::ExpiredSignature
        Legion::Logging.warn 'JWT verify failed: token has expired' if defined?(Legion::Logging)
        raise ExpiredTokenError, 'token has expired'
      rescue ::JWT::VerificationError, ::JWT::IncorrectAlgorithm
        Legion::Logging.warn 'JWT verify failed: signature verification failed' if defined?(Legion::Logging)
        raise InvalidTokenError, 'token signature verification failed'
      rescue ::JWT::DecodeError => e
        Legion::Logging.warn "JWT verify failed: #{e.message}" if defined?(Legion::Logging)
        raise DecodeError, "failed to decode token: #{e.message}"
      end

      def self.decode(token)
        payload, _header = ::JWT.decode(token, nil, false)
        symbolize_keys(payload)
      rescue ::JWT::DecodeError => e
        raise DecodeError, "failed to decode token: #{e.message}"
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

        decode_opts = {
          algorithm:         algorithm,
          verify_expiration: verify_expiration
        }

        if issuers
          decode_opts[:verify_iss] = true
          decode_opts[:iss] = issuers
        end

        if audience
          decode_opts[:verify_aud] = true
          decode_opts[:aud] = audience
        end

        payload, _header = ::JWT.decode(token, public_key, true, decode_opts)
        result = symbolize_keys(payload)
        Legion::Logging.debug "JWT JWKS verify success: sub=#{result[:sub]}, kid=#{kid}" if defined?(Legion::Logging)
        result
      rescue ::JWT::ExpiredSignature
        Legion::Logging.warn "JWT JWKS verify failed: token has expired, kid=#{kid}" if defined?(Legion::Logging)
        raise ExpiredTokenError, 'token has expired'
      rescue ::JWT::VerificationError, ::JWT::IncorrectAlgorithm
        Legion::Logging.warn "JWT JWKS verify failed: signature verification failed, kid=#{kid}" if defined?(Legion::Logging)
        raise InvalidTokenError, 'token signature verification failed'
      rescue ::JWT::InvalidIssuerError
        Legion::Logging.warn "JWT JWKS verify failed: issuer not allowed, kid=#{kid}" if defined?(Legion::Logging)
        raise InvalidTokenError, 'token issuer not allowed'
      rescue ::JWT::InvalidAudError
        Legion::Logging.warn "JWT JWKS verify failed: audience mismatch, kid=#{kid}" if defined?(Legion::Logging)
        raise InvalidTokenError, 'token audience mismatch'
      rescue ::JWT::DecodeError => e
        Legion::Logging.warn "JWT JWKS verify failed: #{e.message}, kid=#{kid}" if defined?(Legion::Logging)
        raise DecodeError, "failed to decode token: #{e.message}"
      end

      def self.decode_header(token)
        parts = token.to_s.split('.')
        raise DecodeError, 'invalid token format' unless parts.size == 3

        header_json = Base64.urlsafe_decode64(parts[0])
        ::JSON.parse(header_json)
      rescue ::JSON::ParserError, ArgumentError => e
        raise DecodeError, "failed to decode token header: #{e.message}"
      end

      def self.validate_algorithm!(algorithm)
        return if SUPPORTED_ALGORITHMS.include?(algorithm)

        raise ArgumentError, "unsupported algorithm: #{algorithm}. Supported: #{SUPPORTED_ALGORITHMS.join(', ')}"
      end

      def self.symbolize_keys(hash)
        hash.transform_keys(&:to_sym)
      end

      private_class_method :validate_algorithm!, :symbolize_keys, :decode_header
    end
  end
end
