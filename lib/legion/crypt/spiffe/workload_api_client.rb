# frozen_string_literal: true

require 'socket'
require 'openssl'

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
      # For environments that cannot make a real SPIRE call (CI, lite mode,
      # no socket present) the client returns a self-signed fallback SVID so
      # that callers never have to special-case the nil case.
      class WorkloadApiClient
        # gRPC content-type and method path for the Workload API FetchX509SVID RPC.
        GRPC_CONTENT_TYPE = 'application/grpc'
        FETCH_X509_METHOD = '/spiffe.workload.SpiffeWorkloadAPI/FetchX509SVID'
        FETCH_JWT_METHOD  = '/spiffe.workload.SpiffeWorkloadAPI/FetchJWTSVID'

        # Handshake + settings frames required to open an HTTP/2 connection.
        HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        HTTP2_SETTINGS_FRAME = [0, 4, 0, 0, 0, 0].pack('NnCCNN')

        CONNECT_TIMEOUT = 5
        READ_TIMEOUT    = 10

        def initialize(socket_path: nil, trust_domain: nil)
          @socket_path  = socket_path  || Legion::Crypt::Spiffe.socket_path
          @trust_domain = trust_domain || Legion::Crypt::Spiffe.trust_domain
        end

        # Fetch an X.509 SVID from the SPIRE Workload API.
        # Returns a populated X509Svid struct.
        # Falls back to a self-signed certificate when the Workload API is unavailable.
        def fetch_x509_svid
          raw = call_workload_api(FETCH_X509_METHOD, '')
          parse_x509_svid_response(raw)
        rescue WorkloadApiError, IOError, Errno::ENOENT, Errno::ECONNREFUSED, Errno::EPIPE => e
          log_warn("[SPIFFE] Workload API unavailable (#{e.message}); using self-signed fallback")
          self_signed_fallback
        end

        # Fetch a JWT SVID from the SPIRE Workload API for the given audience.
        def fetch_jwt_svid(audience:)
          payload  = encode_jwt_request(audience)
          raw      = call_workload_api(FETCH_JWT_METHOD, payload)
          parse_jwt_svid_response(raw, audience)
        rescue WorkloadApiError, IOError, Errno::ENOENT, Errno::ECONNREFUSED, Errno::EPIPE => e
          log_warn("[SPIFFE] JWT SVID fetch failed (#{e.message})")
          raise SvidError, "Failed to fetch JWT SVID for audience '#{audience}': #{e.message}"
        end

        # Returns true when the SPIRE agent socket exists and is reachable.
        def available?
          return false unless ::File.exist?(@socket_path)

          sock = UNIXSocket.new(@socket_path)
          sock.close
          true
        rescue StandardError
          false
        end

        private

        # Minimal HTTP/2 + gRPC unary call over a Unix domain socket.
        # This is intentionally simple: one request frame, one response frame.
        def call_workload_api(method_path, request_body)
          sock = connect_socket
          begin
            send_grpc_request(sock, method_path, request_body)
            read_grpc_response(sock)
          ensure
            sock.close rescue nil # rubocop:disable Style/RescueModifier
          end
        end

        def connect_socket
          raise WorkloadApiError, "SPIRE agent socket not found at '#{@socket_path}'" unless ::File.exist?(@socket_path)

          sock = UNIXSocket.new(@socket_path)
          # Write HTTP/2 connection preface and initial SETTINGS frame.
          sock.write(HTTP2_PREFACE)
          sock.write(HTTP2_SETTINGS_FRAME)
          sock.flush
          sock
        rescue Errno::ENOENT
          raise WorkloadApiError, "SPIRE agent socket not found at '#{@socket_path}'"
        rescue Errno::ECONNREFUSED, Errno::EACCES => e
          raise WorkloadApiError, "Cannot connect to SPIRE agent socket: #{e.message}"
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

        def read_grpc_response(sock)
          # Read until we see a DATA frame containing a gRPC message or timeout.
          deadline = Time.now + READ_TIMEOUT
          buffer   = ''.b

          loop do
            raise WorkloadApiError, 'Workload API read timeout' if Time.now > deadline

            ready = sock.wait_readable(1.0)
            next unless ready

            chunk = sock.read_nonblock(4096, exception: false)
            break if chunk == :wait_readable || chunk.nil?

            buffer += chunk.b
            result  = extract_grpc_body(buffer)
            return result if result
          end

          raise WorkloadApiError, 'No valid gRPC response received from Workload API'
        end

        # Scan the raw HTTP/2 buffer for a DATA frame (type=0x00) that contains
        # a non-empty gRPC message and return the message body bytes.
        def extract_grpc_body(buffer)
          pos = 0
          while pos + 9 <= buffer.bytesize
            frame_length = (buffer.getbyte(pos) << 16) | (buffer.getbyte(pos + 1) << 8) | buffer.getbyte(pos + 2)
            frame_type   = buffer.getbyte(pos + 3)
            pos         += 9 # skip frame header

            if pos + frame_length > buffer.bytesize
              # Incomplete frame — need more data.
              return nil
            end

            payload = buffer.byteslice(pos, frame_length)
            pos    += frame_length

            next unless frame_type.zero? && payload && payload.bytesize >= 5

            # gRPC message: 1-byte compressed flag + 4-byte length + body
            compressed = payload.getbyte(0)
            msg_length = (payload.getbyte(1) << 24) | (payload.getbyte(2) << 16) |
                         (payload.getbyte(3) << 8)  | payload.getbyte(4)
            next if msg_length.zero?

            msg_body = payload.byteslice(5, msg_length)
            next if msg_body.nil? || msg_body.bytesize < msg_length

            # Compressed gRPC responses are not expected from SPIRE; skip them.
            next unless compressed.zero?

            return msg_body
          end
          nil
        end

        # Minimal protobuf encoding for JWTSVIDParams { audience: [string], id: SpiffeID }.
        # We only need field 1 (audience, repeated string).
        def encode_jwt_request(audience)
          audience_bytes = audience.b
          # Field 1, wire type 2 (length-delimited) = tag 0x0A
          "\n#{[audience_bytes.bytesize].pack('C')}#{audience_bytes}"
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
            expiry:     cert.not_after
          )
        rescue OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError => e
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
            expiry:    expiry
          )
        end

        # Build a self-signed X.509 SVID for use when SPIRE is not available.
        def self_signed_fallback
          key  = OpenSSL::PKey::EC.generate('prime256v1')
          cert = OpenSSL::X509::Certificate.new
          cert.version   = 2
          cert.serial    = OpenSSL::BN.rand(128)
          cert.not_before = Time.now
          cert.not_after  = Time.now + 3600

          spiffe_id_str = "#{SPIFFE_SCHEME}://#{@trust_domain}/workload/legion"
          subject       = OpenSSL::X509::Name.parse("/CN=#{spiffe_id_str}")
          cert.subject  = subject
          cert.issuer   = subject
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
            expiry:     cert.not_after
          )
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

        def decode_varint(bytes, pos)
          result = 0
          shift  = 0
          loop do
            byte = bytes.getbyte(pos)
            return [result, pos] if byte.nil?

            pos    += 1
            result |= (byte & 0x7F) << shift
            shift  += 7
            break unless (byte & 0x80).nonzero?
          end
          [result, pos - (shift / 7)]
        end

        # Extract the `exp` claim from the JWT payload without verifying the signature.
        def extract_jwt_expiry(token)
          parts = token.split('.')
          return Time.now + 3600 unless parts.length >= 2

          payload_json = Base64.urlsafe_decode64("#{parts[1]}==")
          claims = begin
            Legion::JSON.parse(payload_json)
          rescue StandardError
            {}
          end
          exp = claims['exp'] || claims[:exp]
          exp ? Time.at(exp.to_i) : Time.now + 3600
        rescue StandardError
          Time.now + 3600
        end

        def log_warn(message)
          Legion::Logging.warn(message) if defined?(Legion::Logging)
        end
      end
    end
  end
end
