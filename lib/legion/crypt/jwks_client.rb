# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'jwt'
require 'legion/logging/helper'

module Legion
  module Crypt
    module JwksClient
      CACHE_TTL = 3600

      @cache = {}
      @mutex = Mutex.new

      class << self
        include Legion::Logging::Helper

        def fetch_keys(jwks_url)
          @mutex.synchronize do
            log.debug "JWKS fetch: #{jwks_url}"
            response = http_get(jwks_url)
            jwks_data = parse_response(response)
            keys = parse_jwks(jwks_data)

            @cache[jwks_url] = { keys: keys, fetched_at: Time.now }
            log.info "JWKS fetched url=#{jwks_url} keys=#{keys.size}"
            keys
          end
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.jwks.fetch_keys', jwks_url: jwks_url)
          raise
        end

        def find_key(jwks_url, kid)
          cached = @mutex.synchronize { @cache[jwks_url] }

          if cached && !expired?(cached[:fetched_at])
            key = cached[:keys][kid]
            if key
              log.debug "JWKS cache hit: kid=#{kid}"
              return key
            end
          end

          keys = fetch_keys(jwks_url)
          key = keys[kid]
          return key if key

          raise Legion::Crypt::JWT::InvalidTokenError, "signing key not found: #{kid}"
        end

        def clear_cache
          @mutex.synchronize { @cache = {} }
          log.info 'JWKS cache cleared'
        end

        private

        def expired?(fetched_at)
          Time.now - fetched_at > CACHE_TTL
        end

        def http_get(url)
          uri = URI.parse(url)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == 'https'
          http.open_timeout = 10
          http.read_timeout = 10

          request = Net::HTTP::Get.new(uri.request_uri)
          response = http.request(request)

          raise Legion::Crypt::JWT::Error, "failed to fetch JWKS: HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

          response.body
        rescue StandardError => e
          raise Legion::Crypt::JWT::Error, "failed to fetch JWKS: #{e.message}" unless e.is_a?(Legion::Crypt::JWT::Error)

          raise
        end

        def parse_response(body)
          parsed = ::JSON.parse(body)
          raise Legion::Crypt::JWT::Error, 'invalid JWKS response: missing keys' unless parsed.is_a?(Hash) && parsed['keys'].is_a?(Array)

          parsed
        rescue ::JSON::ParserError => e
          handle_exception(e, level: :warn, operation: 'crypt.jwks.parse_response')
          raise Legion::Crypt::JWT::Error, "invalid JWKS response: #{e.message}"
        end

        def parse_jwks(jwks_data)
          keys = {}

          jwks_data['keys'].each do |jwk_hash|
            kid = jwk_hash['kid']
            next unless kid

            jwk = ::JWT::JWK.new(jwk_hash)
            keys[kid] = jwk.public_key
          rescue StandardError => e
            handle_exception(e, level: :debug, operation: 'crypt.jwks.parse_jwks', kid: kid)
            next
          end

          keys
        end
      end
    end
  end
end
