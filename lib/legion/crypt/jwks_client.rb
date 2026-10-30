# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'jwt'
require 'legion/logging/helper'
require 'concurrent'

module Legion
  module Crypt
    module JwksClient
      CACHE_TTL = 3600
      MISS_REFRESH_COOLDOWN = 30

      @cache = {}
      @cache_mutex = Mutex.new
      @locks = {}
      @locks_mutex = Mutex.new

      class << self
        include Legion::Logging::Helper

        def fetch_keys(jwks_url)
          with_url_lock(jwks_url) { refresh_keys(jwks_url: jwks_url) }
        end

        def find_key(jwks_url, kid)
          cached = cache_read(jwks_url)
          return cached[:keys][kid] if cached && !expired?(cached[:fetched_at]) && cached[:keys][kid]

          with_url_lock(jwks_url) do
            cached = cache_read(jwks_url)
            fresh = cached && !expired?(cached[:fetched_at])
            return cached[:keys][kid] if fresh && cached[:keys][kid]

            if cached && cached[:refresh_after] && (fresh || cached[:error]) &&
               ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) < cached[:refresh_after]
              raise cached[:error] if cached[:error]

              raise Legion::Crypt::JWT::InvalidTokenError, "signing key not found: #{kid}"
            end

            keys = refresh_keys(jwks_url: jwks_url, requested_kid: kid)
            return keys[kid] if keys[kid]

            raise Legion::Crypt::JWT::InvalidTokenError, "signing key not found: #{kid}"
          end
        end

        def prefetch!(jwks_url)
          Thread.new do
            fetch_keys(jwks_url)
          rescue StandardError => e
            handle_exception(e, level: :debug, operation: 'crypt.jwks.prefetch', jwks_url: jwks_url) if respond_to?(:handle_exception)
            log.debug "JWKS prefetch failed for #{jwks_url}: #{e.message}" if respond_to?(:log)
          end
        end

        def start_background_refresh!(jwks_url, interval: CACHE_TTL)
          stop_background_refresh!

          @refresh_task = Concurrent::TimerTask.new(execution_interval: interval, run_now: false) do
            fetch_keys(jwks_url)
          rescue StandardError => e
            handle_exception(e, level: :debug, operation: 'crypt.jwks.background_refresh', jwks_url: jwks_url) if respond_to?(:handle_exception)
            log.debug "JWKS background refresh failed: #{e.message}" if respond_to?(:log)
          end
          @refresh_task.execute
          log.info "JWKS background refresh started (interval=#{interval}s)" if respond_to?(:log)
        end

        def stop_background_refresh!
          @refresh_task&.shutdown
          @refresh_task = nil
        end

        def clear_cache
          stop_background_refresh!
          @cache_mutex.synchronize { @cache = {} }
          log.info 'JWKS cache cleared'
        end

        private

        def refresh_keys(jwks_url:, requested_kid: nil, **)
          previous = cache_read(jwks_url)
          refreshing_miss = requested_kid && previous && !expired?(previous[:fetched_at])
          log.debug "JWKS fetch: #{jwks_url}"
          keys = parse_jwks(parse_response(http_get(jwks_url)))
          entry = { keys: keys, fetched_at: Time.now }
          if requested_kid && (refreshing_miss || !keys.key?(requested_kid))
            entry[:refresh_after] = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + MISS_REFRESH_COOLDOWN
          end
          cache_write(jwks_url, entry)
          log.info "JWKS fetched url=#{jwks_url} keys=#{keys.size}"
          keys
        rescue StandardError => e
          if requested_kid
            entry = (previous || { keys: {}, fetched_at: nil }).merge(
              error: e, refresh_after: ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + MISS_REFRESH_COOLDOWN
            )
            cache_write(jwks_url, entry)
          end
          handle_exception(e, level: :warn, operation: 'crypt.jwks.fetch_keys', jwks_url: jwks_url)
          raise
        end

        def cache_read(jwks_url)
          @cache_mutex.synchronize { @cache[jwks_url] }
        end

        def cache_write(jwks_url, entry)
          @cache_mutex.synchronize { @cache[jwks_url] = entry }
        end

        def expired?(fetched_at)
          fetched_at.nil? || Time.now - fetched_at > CACHE_TTL
        end

        def http_get(url)
          uri = URI.parse(url)
          raise Legion::Crypt::JWT::Error, 'failed to fetch JWKS: HTTPS is required' unless uri.scheme == 'https'

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          http.verify_mode = jwks_ssl_verify_mode
          http.open_timeout = 10
          http.read_timeout = 10

          request = Net::HTTP::Get.new(uri.request_uri)
          response = http.request(request)

          raise Legion::Crypt::JWT::Error, "failed to fetch JWKS: HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

          response.body
        rescue StandardError => e
          unless e.is_a?(Legion::Crypt::JWT::Error)
            handle_exception(e, level: :warn, operation: 'crypt.jwks.http_get', url: url) if respond_to?(:handle_exception)
            raise Legion::Crypt::JWT::Error, "failed to fetch JWKS: #{e.message}"
          end

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

        def jwks_ssl_verify_mode
          return OpenSSL::SSL::VERIFY_PEER unless defined?(Legion::Settings)

          verify = Legion::Settings[:crypt][:jwt][:jwks_tls_verify]&.to_s
          verify == 'none' ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
        rescue StandardError
          OpenSSL::SSL::VERIFY_PEER
        end

        def with_url_lock(jwks_url, &)
          lock = @locks_mutex.synchronize { @locks[jwks_url] ||= Mutex.new }
          lock.synchronize(&)
        end
      end
    end
  end
end
