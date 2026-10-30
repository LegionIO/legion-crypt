# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/spiffe'
require 'legion/crypt/spiffe/workload_api_client'

RSpec.describe Legion::Crypt::Spiffe::WorkloadApiClient do
  let(:client) { described_class.new(socket_path: '/tmp/fake.sock', trust_domain: 'test.local', allow_x509_fallback: false) }

  describe '#available?' do
    it 'returns false when the socket file does not exist' do
      allow(File).to receive(:exist?).with('/tmp/fake.sock').and_return(false)
      expect(client.available?).to be false
    end

    it 'returns false when the socket exists but connection fails' do
      allow(File).to receive(:exist?).with('/tmp/fake.sock').and_return(true)
      allow(UNIXSocket).to receive(:new).and_raise(Errno::ECONNREFUSED)
      expect(client.available?).to be false
    end

    it 'returns true when the socket is reachable' do
      fake_sock = instance_double(UNIXSocket)
      allow(File).to receive(:exist?).with('/tmp/fake.sock').and_return(true)
      allow(UNIXSocket).to receive(:new).with('/tmp/fake.sock').and_return(fake_sock)
      allow(fake_sock).to receive(:close)
      expect(client.available?).to be true
    end
  end

  describe '#fetch_x509_svid' do
    context 'when the Workload API is unavailable (no socket)' do
      before do
        allow(File).to receive(:exist?).and_return(false)
      end

      it 'fails closed by default' do
        expect { client.fetch_x509_svid }
          .to raise_error(Legion::Crypt::Spiffe::SvidError, /Failed to fetch X.509 SVID/)
      end
    end

    context 'when the Workload API raises a connection error' do
      before do
        allow(File).to receive(:exist?).with('/tmp/fake.sock').and_return(true)
        allow(UNIXSocket).to receive(:new).and_raise(Errno::ECONNREFUSED, 'connection refused')
      end

      it 'raises when fallback is disabled' do
        expect { client.fetch_x509_svid }
          .to raise_error(Legion::Crypt::Spiffe::SvidError, /Failed to fetch X.509 SVID/)
      end
    end

    context 'when explicit fallback is enabled' do
      let(:client) { described_class.new(socket_path: '/tmp/fake.sock', trust_domain: 'test.local', allow_x509_fallback: true) }

      before do
        allow(File).to receive(:exist?).and_return(false)
      end

      it 'returns a self-signed fallback SVID' do
        svid = client.fetch_x509_svid
        expect(svid).to be_a(Legion::Crypt::Spiffe::X509Svid)
        expect(svid.source).to eq(:fallback)
      end

      it 'returns a valid (non-expired) fallback SVID' do
        svid = client.fetch_x509_svid
        expect(svid.valid?).to be true
      end

      it 'encodes the trust domain into the fallback SPIFFE ID' do
        svid = client.fetch_x509_svid
        expect(svid.spiffe_id.trust_domain).to eq('test.local')
      end
    end
  end

  describe '#fetch_jwt_svid' do
    context 'when the socket does not exist' do
      before do
        allow(File).to receive(:exist?).and_return(false)
      end

      it 'raises SvidError' do
        expect { client.fetch_jwt_svid(audience: 'myservice') }
          .to raise_error(Legion::Crypt::Spiffe::SvidError, /myservice/)
      end
    end
  end

  describe 'self-signed fallback' do
    it 'generates a unique serial number each call' do
      allow(client).to receive(:instance_variable_get).with(:@allow_x509_fallback).and_return(true)
      allow(File).to receive(:exist?).and_return(false)
      svid1 = described_class.new(socket_path: '/tmp/fake.sock', trust_domain: 'test.local', allow_x509_fallback: true).fetch_x509_svid
      svid2 = described_class.new(socket_path: '/tmp/fake.sock', trust_domain: 'test.local', allow_x509_fallback: true).fetch_x509_svid
      cert1 = OpenSSL::X509::Certificate.new(svid1.cert_pem)
      cert2 = OpenSSL::X509::Certificate.new(svid2.cert_pem)
      expect(cert1.serial).not_to eq(cert2.serial)
    end

    it 'embeds the SPIFFE URI SAN in the fallback cert' do
      fallback_client = described_class.new(socket_path: '/tmp/fake.sock', trust_domain: 'test.local', allow_x509_fallback: true)
      allow(File).to receive(:exist?).and_return(false)
      svid = fallback_client.fetch_x509_svid
      cert = OpenSSL::X509::Certificate.new(svid.cert_pem)
      san  = cert.extensions.find { |e| e.oid == 'subjectAltName' }
      expect(san).not_to be_nil
      expect(san.value).to include('spiffe://test.local')
    end
  end

  describe 'bounded Workload API exchange' do
    let(:sockets) { UNIXSocket.pair }
    let(:socket) { sockets.first }

    before do
      allow(File).to receive(:exist?).with('/tmp/fake.sock').and_return(true)
      allow(UNIXSocket).to receive(:new).with('/tmp/fake.sock').and_return(socket)
      allow(socket).to receive(:wait_readable).and_return(true)
    end

    after { sockets.each { |entry| entry.close unless entry.closed? } }

    def data_frame(payload:, stream: 1, flags: 0)
      length = payload.bytesize
      [length >> 16, (length >> 8) & 0xFF, length & 0xFF, 0, flags, stream].pack('CCCCCN') + payload
    end

    it 'returns exactly the declared gRPC message from a complete DATA frame' do
      body = 'complete response'.b
      frame = data_frame(payload: "#{[0, body.bytesize].pack('CN')}#{body}trailing message bytes")
      allow(socket).to receive(:read_nonblock).and_return(frame)

      expect(client.send(:call_workload_api, described_class::FETCH_X509_METHOD, '')).to eq(body)
      expect(socket.closed?).to be(true)
    end

    it 'reassembles split gRPC prefixes and bodies across DATA frames and partial socket reads' do
      body = 'fragmented response with binary bytes'.b + "\x00\xFF".b
      grpc = [0, body.bytesize].pack('CN') + body
      frames = data_frame(payload: 'unrelated stream', stream: 3) +
               data_frame(payload: grpc.byteslice(0, 2)) +
               described_class::HTTP2_SETTINGS_FRAME +
               data_frame(payload: grpc.byteslice(2, 8)) +
               data_frame(payload: "\x02".b + grpc.byteslice(10..) + "\x00\x00".b, flags: 8)
      chunks = frames.bytes.each_slice(3).map { |bytes| bytes.pack('C*') }
      chunks.insert(2, :wait_readable)
      allow(socket).to receive(:read_nonblock) { chunks.shift }

      expect(client.send(:call_workload_api, described_class::FETCH_X509_METHOD, '')).to eq(body)
      expect(socket.closed?).to be(true)
    end

    it 'rejects a truncated gRPC message at EOF and closes the socket' do
      frame = data_frame(payload: "#{[0, 50].pack('CN')}short")
      allow(socket).to receive(:read_nonblock).and_return(frame, nil)

      expect { client.fetch_jwt_svid(audience: 'service') }.to raise_error(Legion::Crypt::Spiffe::SvidError, /No valid gRPC response/)
      expect(socket.closed?).to be(true)
    end

    %i[connect preface settings handshake_flush request request_flush read].each do |phase|
      it "bounds blocked #{phase} operations and closes any acquired socket" do
        stub_const('Legion::Crypt::Spiffe::WorkloadApiClient::CONNECT_TIMEOUT', 0.02)
        stub_const('Legion::Crypt::Spiffe::WorkloadApiClient::READ_TIMEOUT', 0.05)
        blocked = Queue.new
        allow(UNIXSocket).to receive(:new) { blocked.pop } if phase == :connect
        writes = 0
        flushes = 0
        allow(socket).to receive(:write) do |bytes|
          writes += 1
          blocked.pop if { preface: 1, settings: 2, request: 3 }[phase] == writes
          bytes.bytesize
        end
        allow(socket).to receive(:flush) do
          flushes += 1
          blocked.pop if { handshake_flush: 1, request_flush: 2 }[phase] == flushes
        end
        allow(socket).to receive(:read_nonblock) { blocked.pop }
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

        expect do
          Timeout.timeout(0.5) { client.fetch_jwt_svid(audience: 'service') }
        end.to raise_error(Legion::Crypt::Spiffe::SvidError, /timed out/)
        expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.2
        expect(socket.closed?).to be(true) unless phase == :connect
      end
    end

    it 'does not restart the operation deadline after request writes finish' do
      stub_const('Legion::Crypt::Spiffe::WorkloadApiClient::CONNECT_TIMEOUT', 0.1)
      stub_const('Legion::Crypt::Spiffe::WorkloadApiClient::READ_TIMEOUT', 0.12)
      blocked = Queue.new
      allow(socket).to receive(:write) do |bytes|
        sleep(0.025)
        bytes.bytesize
      end
      allow(socket).to receive(:read_nonblock) { blocked.pop }
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      expect do
        Timeout.timeout(0.5) { client.fetch_jwt_svid(audience: 'service') }
      end.to raise_error(Legion::Crypt::Spiffe::SvidError, /timed out/)
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.17
      expect(socket.closed?).to be(true)
    end

    it 'bounds availability probes when connecting stalls' do
      stub_const('Legion::Crypt::Spiffe::WorkloadApiClient::CONNECT_TIMEOUT', 0.02)
      blocked = Queue.new
      allow(UNIXSocket).to receive(:new) { blocked.pop }

      expect(Timeout.timeout(0.5) { client.available? }).to be(false)
    end
  end

  describe 'protobuf audience lengths' do
    it 'uses canonical varints at the one-byte and two-byte boundaries' do
      { 127 => [127], 128 => [128, 1], 16_384 => [128, 128, 1] }.each do |length, prefix|
        audience = 'a' * length
        encoded = client.send(:encode_jwt_request, audience)
        expect(encoded.byteslice(0, prefix.length + 1).bytes).to eq([10, *prefix])
        expect(client.send(:extract_proto_field, encoded, field_number: 1)).to eq(audience)
      end
    end
  end

  describe 'minimal protobuf helpers (private, tested via send)' do
    describe '#decode_varint' do
      it 'decodes a single-byte varint' do
        bytes = "\x05".b
        value, consumed = client.send(:decode_varint, bytes, 0)
        expect(value).to eq(5)
        expect(consumed).to eq(1)
      end

      it 'decodes a two-byte varint (value 300 = 0xAC 0x02)' do
        bytes = "\xAC\x02".b
        value, = client.send(:decode_varint, bytes, 0)
        expect(value).to eq(300)
      end

      it 'returns 0 consumed when pos is past end of bytes' do
        bytes = ''.b
        value, consumed = client.send(:decode_varint, bytes, 0)
        expect(value).to eq(0)
        expect(consumed).to eq(0)
      end
    end

    describe '#extract_proto_field' do
      it 'returns nil when field is not present' do
        result = client.send(:extract_proto_field, ''.b, field_number: 1)
        expect(result).to be_nil
      end

      it 'extracts a length-delimited field (wire type 2)' do
        # Build a minimal protobuf: field 1, wire type 2, length 5, value "hello"
        payload = "\x0A\x05hello".b
        result  = client.send(:extract_proto_field, payload, field_number: 1)
        expect(result).to eq('hello'.b)
      end

      it 'skips varint fields (wire type 0) before the target field' do
        # Field 1 varint=42, field 2 length-delimited="world"
        payload = "\x08\x2A\x12\x05world".b
        result  = client.send(:extract_proto_field, payload, field_number: 2)
        expect(result).to eq('world'.b)
      end
    end

    describe '#extract_jwt_expiry' do
      it 'extracts exp from a real-looking JWT payload segment' do
        exp    = (Time.now + 3600).to_i
        claims = { 'exp' => exp }.to_json
        b64    = Base64.urlsafe_encode64(claims, padding: false)
        token  = "header.#{b64}.sig"
        result = client.send(:extract_jwt_expiry, token)
        expect(result.to_i).to be_within(2).of(exp)
      end

      it 'returns a future time when JWT has no exp claim' do
        claims = { 'sub' => 'test' }.to_json
        b64    = Base64.urlsafe_encode64(claims, padding: false)
        token  = "header.#{b64}.sig"
        result = client.send(:extract_jwt_expiry, token)
        expect(result).to be > Time.now
      end

      it 'returns a future time for a malformed token' do
        result = client.send(:extract_jwt_expiry, 'not.a.jwt')
        expect(result).to be > Time.now
      end
    end
  end
end
