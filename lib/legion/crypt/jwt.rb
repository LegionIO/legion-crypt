# frozen_string_literal: true

require 'jwt'
require 'securerandom'

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

        ::JWT.encode(claims, signing_key, algorithm)
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
        symbolize_keys(payload)
      rescue ::JWT::ExpiredSignature
        raise ExpiredTokenError, 'token has expired'
      rescue ::JWT::VerificationError, ::JWT::IncorrectAlgorithm
        raise InvalidTokenError, 'token signature verification failed'
      rescue ::JWT::DecodeError => e
        raise DecodeError, "failed to decode token: #{e.message}"
      end

      def self.decode(token)
        payload, _header = ::JWT.decode(token, nil, false)
        symbolize_keys(payload)
      rescue ::JWT::DecodeError => e
        raise DecodeError, "failed to decode token: #{e.message}"
      end

      def self.validate_algorithm!(algorithm)
        return if SUPPORTED_ALGORITHMS.include?(algorithm)

        raise ArgumentError, "unsupported algorithm: #{algorithm}. Supported: #{SUPPORTED_ALGORITHMS.join(', ')}"
      end

      def self.symbolize_keys(hash)
        hash.transform_keys(&:to_sym)
      end

      private_class_method :validate_algorithm!, :symbolize_keys
    end
  end
end
