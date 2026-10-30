# frozen_string_literal: true

require 'legion/logging/helper'
require 'socket'
require 'openssl'
require 'timeout'

module Legion
  module Crypt
    module Spiffe
      # Minimal SPIFFE Workload API client.
      #
      # The SPIFFE Workload API is served over a Unix domain socket by a local
      # SPIRE agent.  The wire protocol is gRPC/HTTP2, but we avoid pulling in
      # a full gRPC stack by implementing just enough of the HTTP/2 framing to
      # send a single unary RPC call and parse a single response.
      #
      # X.509 fallback is available only when explicitly enabled; otherwise
      # unavailable or invalid Workload API responses fail closed.
      class WorkloadApiClient
        include Legion::Logging::Helper

        # gRPC content-type and method path for the Workload API FetchX509SVID RPC.
        GRPC_CONTENT_TYPE = 'application/grpc'
        FETCH_X509_METHOD = '/spiffe.workload.SpiffeWorkloadAPI/FetchX509SVID'
        FETCH_JWT_METHOD  = '/spiffe.workload.SpiffeWorkloadAPI/FetchJWTSVID'

        # Handshake + settings frames required to open an HTTP/2 connection.
        HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        HTTP2_SETTINGS_FRAME = "\x00\x00\x00\x04\x00\x00\x00\x00\x00".b

        CONNECT_TIMEOUT = 5
        READ_TIMEOUT    = 10

        def initialize(socket_path: nil, trust_domain: nil, allow_x509_fallback: nil)
          @socket_path         = socket_path  || Legion::Crypt::Spiffe.socket_path
          @trust_domain        = trust_domain || Legion::Crypt::Spiffe.trust_domain
          @allow_x509_fallback = allow_x509_fallback.nil? ? Legion::Crypt::Spiffe.allow_x509_fallback? : allow_x509_fallback
        end

        # Fetch an X.509 SVID from the SPIRE Workload API.
        # Returns a populated X509Svid struct.
        # Uses a self-signed fallback only when explicitly enabled.
        def fetch_x509_svid
          log.info("[SPIFFE] Fetching X.509 SVID from Workload API socket=#{@socket_path}")
          raw = call_workload_api(FETCH_X509_METHOD, '')
          parse_x509_svid_response(raw)
        rescue WorkloadApiError, IOError, Errno::ENOENT, Errno::ECONNREFUSED, Errno::EPIPE => e
          handle_exception(e, level: :warn, operation: 'crypt.spiffe.workload_api_client.fetch_x509_svid',
                           socket_path: @socket_path, fallback: @allow_x509_fallback)
          unless @allow_x509_fallback
            log.error("[SPIFFE] Workload API unavailable (#{e.message}); X.509 fallback disabled")
            raise SvidError, "Failed to fetch X.509 SVID: #{e.message}"
          end

          log.warn("[SPIFFE] Workload API unavailable (#{e.message}); using self-signed fallback")
          self_signed_fallback
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.spiffe.workload_api_client.fetch_x509_svid',
                           socket_path: @socket_path)
          log.error("[SPIFFE] X.509 SVID fetch failed: #{e.message}")
          raise
        end

        # Fetch a JWT SVID from the SPIRE Workload API for the given audience.
        def fetch_jwt_svid(audience:)
          log.info("[SPIFFE] Fetching JWT SVID from Workload API audience=#{audience}")
          payload  = encode_jwt_request(audience)
          raw      = call_workload_api(FETCH_JWT_METHOD, payload)
          parse_jwt_svid_response(raw, audience)
        rescue WorkloadApiError, IOError, Errno::ENOENT, Errno::ECONNREFUSED, Errno::EPIPE => e
          handle_exception(e, level: :warn, operation: 'crypt.spiffe.workload_api_client.fetch_jwt_svid',
                           socket_path: @socket_path, audience: audience)
          log.warn("[SPIFFE] JWT SVID fetch failed (#{e.message})")
          raise SvidError, "Failed to fetch JWT SVID for audience '#{audience}': #{e.message}"
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.spiffe.workload_api_client.fetch_jwt_svid',
                           socket_path: @socket_path, audience: audience)
          log.error("[SPIFFE] JWT SVID fetch failed: #{e.message}")
          raise SvidError, "Failed to fetch JWT SVID for audience '#{audience}': #{e.message}"
        end

        # Returns true when the SPIRE agent socket exists and is reachable.
        def available?
          with_socket_deadline(deadline: ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + CONNECT_TIMEOUT) do
            return false unless ::File.exist?(@socket_path)

            sock = UNIXSocket.new(@socket_path)
            sock.close
            true
          end
        rescue StandardError => e
          handle_exception(e, level: :debug, operation: 'crypt.spiffe.workload_api_client.available',
                           socket_path: @socket_path)
          false
        end

        private

        # Minimal HTTP/2 + gRPC unary call over a Unix domain socket.
        # One bounded request; response DATA frames may split a gRPC message.
        def call_workload_api(method_path, request_body)
          log.debug("[SPIFFE] Calling Workload API method=#{method_path}")
          deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + READ_TIMEOUT
          sock = nil
          with_socket_deadline(deadline: deadline) do
            connect_deadline = [deadline, ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + CONNECT_TIMEOUT].min
            with_socket_deadline(deadline: connect_deadline) do
              raise WorkloadApiError, "SPIRE agent socket not found at '#{@socket_path}'" unless ::File.exist?(@socket_path)

              sock = UNIXSocket.new(@socket_path)
              sock.write(HTTP2_PREFACE)
              sock.write(HTTP2_SETTINGS_FRAME)
              sock.flush
              send_grpc_request(sock, method_path, request_body)
            end
            read_grpc_response(sock, deadline: deadline)
          end
        rescue Errno::EACCES => e
          raise WorkloadApiError, "Cannot connect to SPIRE agent socket: #{e.message}"
        ensure
          close_workload_api_socket(sock, method_path) if sock
        end

        def close_workload_api_socket(sock, method_path)
          sock.close
        rescue StandardError => e
          handle_exception(e, level: :debug, operation: 'crypt.spiffe.workload_api_client.close_socket',
                           method_path: method_path, socket_path: @socket_path)
          nil
        end

        def with_socket_deadline(deadline:, &)
          remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
          raise WorkloadApiError, 'Workload API operation timed out' unless remaining.positive?

          Timeout.timeout(remaining, &)
        rescue Timeout::Error
          raise WorkloadApiError, 'Workload API operation timed out'
        end

        # Build and send a minimal gRPC/HTTP2 HEADERS + DATA frame.
        # We encode only the fields the SPIRE agent needs to accept the request.
        def send_grpc_request(sock, method_path, body)
          headers = build_grpc_headers(method_path)
          headers_frame = encode_http2_frame(type: 0x01, flags: 0x04, stream_id: 1, payload: headers)
          data_frame    = encode_grpc_data_frame(body)
          sock.write(headers_frame + data_frame)
          sock.flush
        end

        def build_grpc_headers(method_path)
          # Minimal set of pseudo-headers and gRPC headers encoded as HPACK literals.
          # We use the no-indexing literal representation for simplicity.
          encode_header(':method', 'POST') +
            encode_header(':path', method_path) +
            encode_header(':scheme', 'http') +
            encode_header(':authority', 'localhost') +
            encode_header('content-type', GRPC_CONTENT_TYPE) +
            encode_header('te', 'trailers')
        end

        # Encode a single HPACK literal header field (no indexing).
        def encode_header(name, value)
          name_bytes  = name.b
          value_bytes = value.b
          [0x00].pack('C') +
            encode_hpack_string(name_bytes) +
            encode_hpack_string(value_bytes)
        end

        def encode_hpack_string(bytes)
          # Length prefix (non-Huffman).
          len = bytes.bytesize
          if len < 128
            [len].pack('C') + bytes
          else
            # Multi-byte length encoding (RFC 7541 §5.1).
            parts = [0x80 | (len & 0x7F)].pack('C')
            len >>= 7
            parts += [(len.positive? ? 0x80 : 0x00) | (len & 0x7F)].pack('C')
            parts + bytes
          end
        end

        # Encode a gRPC message as a DATA frame (5-byte gRPC header + body).
        def encode_grpc_data_frame(body)
          grpc_header = [0, body.bytesize].pack('CN') # compressed-flag + length
          payload     = grpc_header + body.b
          encode_http2_frame(type: 0x00, flags: 0x01, stream_id: 1, payload: payload)
        end

        # Build an HTTP/2 frame (RFC 7540 §4.1).
        def encode_http2_frame(type:, flags:, stream_id:, payload:)
          length = payload.bytesize
          # 3-byte length + 1-byte type + 1-byte flags + 4-byte stream_id (MSB=0)
          [length >> 16, (length >> 8) & 0xFF, length & 0xFF, type, flags].pack('CCCCC') +
            [stream_id & 0x7FFFFFFF].pack('N') +
            payload.b
        end

        def read_grpc_response(sock, deadline:)
          buffer = ''.b
          message = ''.b
          loop do
            remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
            raise WorkloadApiError, 'Workload API read timeout' unless remaining.positive?
            next unless sock.wait_readable(remaining)

            chunk = sock.read_nonblock(4096, exception: false)
            next if chunk == :wait_readable
            break if chunk.nil?

            buffer << chunk
            result = extract_grpc_body(buffer, message: message)
            return result unless result.nil?
          end

          raise WorkloadApiError, 'No valid gRPC response received from Workload API'
        end

        # Consume complete HTTP/2 frames and accumulate stream 1 DATA bytes.
        # The gRPC prefix and body can each span multiple frames and reads.
        def extract_grpc_body(buffer, message:)
          pos = 0
          while pos + 9 <= buffer.bytesize
            frame_length = (buffer.getbyte(pos) << 16) | (buffer.getbyte(pos + 1) << 8) | buffer.getbyte(pos + 2)
            frame_end = pos + 9 + frame_length
            break if frame_end > buffer.bytesize

            frame_type = buffer.getbyte(pos + 3)
            flags = buffer.getbyte(pos + 4)
            stream_id = buffer.unpack1('N', offset: pos + 5) & 0x7FFFFFFF
            pos += 9
            if frame_type.zero? && stream_id == 1
              if flags.anybits?(0x08)
                padding = buffer.getbyte(pos)
                raise WorkloadApiError, 'Invalid padded HTTP/2 DATA frame' if frame_length.zero? || padding >= frame_length

                pos += 1
                frame_length -= padding + 1
              end
              message << buffer.byteslice(pos, frame_length)
            end
            pos = frame_end
            next if message.bytesize < 5

            raise WorkloadApiError, 'Compressed gRPC responses are unsupported' unless message.getbyte(0).zero?

            length = message.unpack1('N', offset: 1)
            return message.byteslice(5, length) if message.bytesize >= length + 5
          end
          buffer.slice!(0, pos) if pos.positive?
          nil
        end

        # Minimal protobuf encoding for JWTSVIDParams { audience: [string], id: SpiffeID }.
        # We only need field 1 (audience, repeated string).
        def encode_jwt_request(audience)
          audience_bytes = audience.b
          # Field 1, wire type 2 (length-delimited) = tag 0x0A
          "\x0A".b + encode_varint(audience_bytes.bytesize) + audience_bytes
        end

        def encode_varint(value)
          bytes = ''.b
          loop do
            byte = value & 0x7F
            value >>= 7
            bytes << (value.zero? ? byte : byte | 0x80)
            break if value.zero?
          end
          bytes
        end

        # Parse the raw protobuf bytes from FetchX509SVIDResponse into an X509Svid.
        # Field layout (spiffe.workload.X509SVIDResponse.svids[0]):
        #   svids: repeated X509SVID (field 1)
        #     spiffe_id: string (field 1)
        #     x509_svid: bytes (field 2) — DER-encoded cert chain
        #     x509_svid_key: bytes (field 3) — DER-encoded private key (PKCS8)
        #     bundle: bytes (field 4) — DER-encoded CA bundle
        def parse_x509_svid_response(raw)
          svid_bytes = extract_proto_field(raw, field_number: 1)
          raise SvidError, 'Empty X.509 SVID response from Workload API' if svid_bytes.nil? || svid_bytes.empty?

          spiffe_id_str = extract_proto_string(svid_bytes, field_number: 1)
          cert_der      = extract_proto_bytes(svid_bytes, field_number: 2)
          key_der       = extract_proto_bytes(svid_bytes, field_number: 3)
          bundle_der    = extract_proto_bytes(svid_bytes, field_number: 4)

          raise SvidError, 'X.509 SVID missing certificate data' if cert_der.nil? || cert_der.empty?
          raise SvidError, 'X.509 SVID missing private key data' if key_der.nil? || key_der.empty?

          cert       = OpenSSL::X509::Certificate.new(cert_der)
          key        = OpenSSL::PKey.read(key_der)
          bundle_pem = bundle_der ? OpenSSL::X509::Certificate.new(bundle_der).to_pem : nil
          spiffe_id  = Legion::Crypt::Spiffe.parse_id(spiffe_id_str)

          X509Svid.new(
            spiffe_id:  spiffe_id,
            cert_pem:   cert.to_pem,
            key_pem:    key.private_to_pem,
            bundle_pem: bundle_pem,
            expiry:     cert.not_after,
            source:     :spire
          )
        rescue OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError => e
          handle_exception(e, level: :error, operation: 'crypt.spiffe.workload_api_client.parse_x509_svid_response')
          raise SvidError, "Failed to parse X.509 SVID: #{e.message}"
        end

        # Parse the raw protobuf bytes from FetchJWTSVIDResponse into a JwtSvid.
        # Field layout:
        #   svids: repeated JWTSVID (field 1)
        #     spiffe_id: string (field 1)
        #     svid: string (field 2) — the JWT token
        def parse_jwt_svid_response(raw, audience)
          svid_bytes = extract_proto_field(raw, field_number: 1)
          raise SvidError, 'Empty JWT SVID response from Workload API' if svid_bytes.nil? || svid_bytes.empty?

          spiffe_id_str = extract_proto_string(svid_bytes, field_number: 1)
          token         = extract_proto_string(svid_bytes, field_number: 2)

          raise SvidError, 'JWT SVID missing token' if token.nil? || token.empty?

          expiry    = extract_jwt_expiry(token)
          spiffe_id = Legion::Crypt::Spiffe.parse_id(spiffe_id_str)

          JwtSvid.new(
            spiffe_id: spiffe_id,
            token:     token,
            audience:  audience,
            expiry:    expiry,
            source:    :spire
          )
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.spiffe.workload_api_client.parse_jwt_svid_response',
                           audience: audience)
          raise
        end

        # Build a self-signed X.509 SVID for use when SPIRE is not available.
        # The SPIFFE ID is placed in the SAN URI extension per the SPIFFE spec.
        # The Subject CN is a plain workload name (no URI) so OpenSSL parses cleanly.
        def self_signed_fallback
          log.info("[SPIFFE] Generating self-signed fallback SVID trust_domain=#{@trust_domain}")
          key  = OpenSSL::PKey::EC.generate('prime256v1')
          cert = OpenSSL::X509::Certificate.new
          cert.version    = 2
          cert.serial     = OpenSSL::BN.rand(128)
          cert.not_before = Time.now
          cert.not_after  = Time.now + 3600

          spiffe_id_str = "#{SPIFFE_SCHEME}://#{@trust_domain}/workload/legion"
          subject         = OpenSSL::X509::Name.parse('/CN=legion-fallback-svid')
          cert.subject    = subject
          cert.issuer     = subject
          cert.public_key = key

          ext_factory = OpenSSL::X509::ExtensionFactory.new(cert, cert)
          cert.add_extension(ext_factory.create_extension('subjectAltName', "URI:#{spiffe_id_str}", false))
          cert.add_extension(ext_factory.create_extension('basicConstraints', 'CA:FALSE', true))
          cert.sign(key, OpenSSL::Digest.new('SHA256'))

          X509Svid.new(
            spiffe_id:  Legion::Crypt::Spiffe.parse_id(spiffe_id_str),
            cert_pem:   cert.to_pem,
            key_pem:    key.private_to_pem,
            bundle_pem: nil,
            expiry:     cert.not_after,
            source:     :fallback
          )
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.spiffe.workload_api_client.self_signed_fallback',
                           trust_domain: @trust_domain)
          log.error("[SPIFFE] Self-signed fallback generation failed: #{e.message}")
          raise
        end

        # --- Minimal protobuf decoder ---
        # Only handles wire types 0 (varint) and 2 (length-delimited).

        def extract_proto_field(bytes, field_number:)
          pos = 0
          while pos < bytes.bytesize
            tag, consumed = decode_varint(bytes, pos)
            pos          += consumed
            wire_type     = tag & 0x07
            field         = tag >> 3

            case wire_type
            when 0 # varint — skip
              _, consumed = decode_varint(bytes, pos)
              pos        += consumed
            when 2 # length-delimited
              len, consumed = decode_varint(bytes, pos)
              pos          += consumed
              data          = bytes.byteslice(pos, len)
              pos          += len
              return data if field == field_number
            else
              break # Unknown wire type — stop parsing
            end
          end
          nil
        end

        def extract_proto_string(bytes, field_number:)
          raw = extract_proto_field(bytes, field_number: field_number)
          raw&.force_encoding('UTF-8')
        end

        alias extract_proto_bytes extract_proto_field

        # Decode a protobuf varint starting at +start+ in +bytes+.
        # Returns [decoded_value, bytes_consumed].
        def decode_varint(bytes, start)
          result  = 0
          shift   = 0
          current = start
          loop do
            byte = bytes.getbyte(current)
            return [result, 0] if byte.nil?

            current += 1
            result  |= (byte & 0x7F) << shift
            shift   += 7
            break unless (byte & 0x80).nonzero?
          end
          [result, current - start]
        end

        # Extract the `exp` claim from the JWT payload without verifying the signature.
        def extract_jwt_expiry(token)
          parts = token.split('.')
          return Time.now + 3600 unless parts.length >= 2

          payload_json = Base64.urlsafe_decode64("#{parts[1]}==")
          claims = begin
            Legion::JSON.parse(payload_json)
          rescue StandardError => e
            handle_exception(e, level: :debug, operation: 'crypt.spiffe.workload_api_client.extract_jwt_expiry')
            {}
          end
          exp = claims['exp'] || claims[:exp]
          exp ? Time.at(exp.to_i) : Time.now + 3600
        rescue StandardError => e
          handle_exception(e, level: :debug, operation: 'crypt.spiffe.workload_api_client.extract_jwt_expiry')
          Time.now + 3600
        end
      end
    end
  end
end
