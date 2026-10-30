# frozen_string_literal: true

require 'faraday'
require 'legion/json'
require 'openssl'
require 'uri'

module Legion
  module Crypt
    module Vault
      class HTTPError < StandardError
        attr_reader :code, :errors, :address

        def initialize(code:, errors: [], address: nil)
          @code = Integer(code)
          @errors = Array(errors)
          @address = address
          super("Vault HTTP #{@code}#{": #{@errors.join('; ')}" unless @errors.empty?}")
        end
      end

      class HTTPClientError < HTTPError; end
      class HTTPServerError < HTTPError; end
    end

    class VaultClient
      CONNECTION_ATTRIBUTES = %i[address ssl_verify ca cert key timeout].freeze

      attr_reader(*CONNECTION_ATTRIBUTES, :logical, :sys, :auth_token, :token)
      attr_accessor :namespace

      def initialize(address:, token: nil, namespace: nil, tls: {}, timeout: 5)
        @address = validate_address(address: address)
        @timeout = validate_timeout(timeout: timeout)
        @token = token
        @namespace = namespace
        @ssl_verify = tls[:verify] != false && tls[:verify].to_s != 'none'
        @ca = tls[:ca]
        @cert = tls[:cert]
        @key = tls[:key]
        @mutex = Mutex.new
        @retired = false
        @logical = Logical.new(client: self)
        @sys = Sys.new(client: self)
        @auth_token = AuthToken.new(client: self)
      end

      CONNECTION_ATTRIBUTES.each do |attribute|
        define_method(:"#{attribute}=") do |value|
          value = validate_address(address: value) if attribute == :address
          value = validate_timeout(timeout: value) if attribute == :timeout
          @mutex.synchronize do
            return value if instance_variable_get(:"@#{attribute}") == value

            previous = @connection
            @connection = nil
            instance_variable_set(:"@#{attribute}", value)
            previous&.close
          end
          value
        end
      end

      def token=(value)
        @mutex.synchronize do
          raise IOError, 'Vault client has been shut down' if @retired

          @token = value
        end
      end

      def kv(mount:)
        KV.new(client: self, mount: mount)
      end

      def put(path:, body:, headers: {})
        request(method: :put, path: path, body: body, headers: headers) || {}
      end

      def request(method:, path:, body: nil, headers: {}, nil_on_not_found: false)
        connection, request_headers, address = @mutex.synchronize do
          raise IOError, 'Vault client has been shut down' if @retired

          [@connection ||= build_connection, vault_headers(headers: headers), @address]
        end
        payload = body.is_a?(String) || body.nil? ? body : Legion::JSON.dump(body)
        response = connection.run_request(method, request_path(path: path), payload, request_headers)
        return nil if nil_on_not_found && response.status == 404

        decode_response(response: response, address: address)
      end

      def shutdown
        @mutex.synchronize do
          @retired = true
          previous = @connection
          @connection = nil
          previous&.close
        end
        nil
      end

      def inspect
        "#<#{self.class}>"
      end

      class Logical
        def initialize(client:)
          @client = client
        end

        def read(path:)
          Secret.decode(data: @client.request(method: :get, path: path, nil_on_not_found: true))
        end

        def write(path:, data:)
          Secret.decode(data: @client.put(path: path, body: data))
        end

        def delete(path:)
          @client.request(method: :delete, path: path)
          true
        end
      end

      class Sys
        class HealthStatus
          def initialize(data:)
            @initialized = data[:initialized]
          end

          def initialized?
            @initialized == true
          end
        end

        def initialize(client:)
          @client = client
        end

        def health_status
          HealthStatus.new(data: @client.request(method: :get, path: 'sys/health'))
        end

        def mounts
          @client.request(method: :get, path: 'sys/mounts').fetch(:data)
        end

        def renew(lease_id:)
          Secret.decode(data: @client.put(path: 'sys/leases/renew', body: { lease_id: lease_id }))
        end

        def revoke(lease_id:)
          @client.put(path: 'sys/leases/revoke', body: { lease_id: lease_id })
          true
        end
      end

      class AuthToken
        def initialize(client:)
          @client = client
        end

        def renew_self
          Secret.decode(data: @client.put(path: 'auth/token/renew-self', body: {}))
        end

        def revoke_self
          @client.put(path: 'auth/token/revoke-self', body: {})
          true
        end
      end

      class KV
        def initialize(client:, mount:)
          @client = client
          mount = mount.to_s
          first = mount.index(%r{[^/]})
          @mount = first ? mount[first..mount.rindex(%r{[^/]})] : ''
        end

        def read(path:)
          response = @client.request(method: :get, path: "#{@mount}/data/#{path}", nil_on_not_found: true)
          return nil if response.nil?

          Secret.decode(data: response.merge(data: response.dig(:data, :data)))
        end

        def write(path:, data:)
          Secret.decode(data: @client.put(path: "#{@mount}/data/#{path}", body: { data: data }))
        end

        def read_metadata(path:)
          Secret.decode(data: @client.request(method: :get, path: "#{@mount}/metadata/#{path}", nil_on_not_found: true))
        end
      end

      class Secret
        attr_reader :data, :auth, :lease_id, :lease_duration

        def self.decode(data:)
          return nil if data.nil? || data.empty?

          new(data: data)
        end

        def initialize(data:)
          @data = data[:data]
          @auth = Auth.new(data: data[:auth]) unless data[:auth].nil?
          @lease_id = data[:lease_id]
          @lease_duration = data[:lease_duration]
          @renewable = data[:renewable]
        end

        def renewable?
          @renewable == true
        end

        def inspect
          "#<#{self.class}>"
        end
      end

      class Auth
        attr_reader :client_token, :lease_duration, :policies, :metadata

        def initialize(data:)
          @client_token = data[:client_token]
          @lease_duration = data[:lease_duration]
          @policies = data[:policies]
          @metadata = data[:metadata]
          @renewable = data[:renewable]
        end

        def renewable?
          @renewable == true
        end

        def inspect
          "#<#{self.class}>"
        end
      end

      private

      def validate_address(address:)
        uri = URI.parse(address.to_s)
        unless uri.is_a?(URI::HTTP) && uri.host && !uri.userinfo && !uri.query && !uri.fragment
          raise ArgumentError, 'Vault address must be an HTTP(S) URL without credentials, query, or fragment'
        end

        uri.to_s.freeze
      rescue URI::InvalidURIError
        raise ArgumentError, 'Vault address must be a valid HTTP(S) URL'
      end

      def validate_timeout(timeout:)
        seconds = Float(timeout)
        raise ArgumentError, 'Vault timeout must be positive and finite' unless seconds.positive? && seconds.finite?

        seconds
      end

      def vault_headers(headers:)
        result = Faraday::Utils::Headers.new('Accept' => 'application/json', 'Content-Type' => 'application/json')
        result.update(headers)
        result.delete('X-Vault-Token')
        result.delete('X-Vault-Namespace')
        result['X-Vault-Token'] = @token unless @token.nil?
        result['X-Vault-Namespace'] = @namespace unless @namespace.nil?
        result
      end

      def request_path(path:)
        relative = path.to_s.sub(%r{\A/v1(?:/|\z)}, '').sub(%r{\A/+}, '')
        encoded = relative.split('/', -1).map do |segment|
          if ['.', '..'].include?(segment)
            segment.gsub('.', '%2E')
          else
            URI.encode_www_form_component(segment).gsub('+', '%20')
          end
        end
        "/v1/#{encoded.join('/')}"
      end

      def build_connection
        Faraday.new(url: @address, ssl: tls_options) do |connection|
          connection.options.timeout = @timeout
          connection.options.open_timeout = @timeout
          connection.options.read_timeout = @timeout
          connection.options.write_timeout = @timeout
          connection.adapter :net_http
        end
      end

      def tls_options
        options = { verify: @ssl_verify != false && @ssl_verify.to_s != 'none' }
        if @ca
          if @ca.include?('-----BEGIN')
            store = OpenSSL::X509::Store.new
            certificates = @ca.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
            raise ArgumentError, 'Vault CA PEM contains no certificates' if certificates.empty?

            certificates.each { |certificate| store.add_cert(OpenSSL::X509::Certificate.new(certificate)) }
            options[:cert_store] = store
          else
            options[:ca_file] = @ca
          end
        end
        options[:client_cert] = tls_certificate(certificate: @cert) if @cert
        options[:client_key] = tls_key(key: @key) if @key
        options
      end

      def tls_certificate(certificate:)
        return certificate if certificate.is_a?(OpenSSL::X509::Certificate)

        pem = certificate.include?('-----BEGIN') ? certificate : File.read(certificate)
        certificates = pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
        return OpenSSL::X509::Certificate.new(pem) if certificates.length < 2

        certificates.map { |entry| OpenSSL::X509::Certificate.new(entry) }
      end

      def tls_key(key:)
        return key if key.is_a?(OpenSSL::PKey::PKey)

        OpenSSL::PKey.read(key.include?('-----BEGIN') ? key : File.read(key))
      end

      def decode_response(response:, address:)
        status = response.status
        unless (200..299).cover?(status)
          error_class = if (400..499).cover?(status)
                          Legion::Crypt::Vault::HTTPClientError
                        elsif (500..599).cover?(status)
                          Legion::Crypt::Vault::HTTPServerError
                        else
                          Legion::Crypt::Vault::HTTPError
                        end
          begin
            decoded = response.body.nil? || response.body.empty? ? {} : Legion::JSON.load(response.body)
          rescue Legion::JSON::ParseError
            raise error_class.new(code: status, errors: [response.body.to_s], address: address)
          end
          errors = decoded.is_a?(Hash) ? decoded[:errors] : [response.body.to_s]
          raise error_class.new(code: status, errors: errors, address: address)
        end
        return nil if status == 204 || response.body.nil? || response.body.empty?

        Legion::JSON.load(response.body)
      end
    end
  end
end
