# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/spiffe'

RSpec.describe Legion::Crypt::Spiffe do
  describe '.parse_id' do
    it 'parses a valid SPIFFE ID with a workload path' do
      id = described_class.parse_id('spiffe://example.org/ns/default/sa/myapp')
      expect(id.trust_domain).to eq('example.org')
      expect(id.path).to eq('/ns/default/sa/myapp')
    end

    it 'parses a SPIFFE ID with only a trust domain (empty path)' do
      id = described_class.parse_id('spiffe://example.org')
      expect(id.trust_domain).to eq('example.org')
      expect(id.path).to eq('/')
    end

    it 'returns a SpiffeId struct' do
      id = described_class.parse_id('spiffe://legion.internal/workload/foo')
      expect(id).to be_a(Legion::Crypt::Spiffe::SpiffeId)
    end

    it 'round-trips to string correctly' do
      raw = 'spiffe://legion.internal/workload/bar'
      expect(described_class.parse_id(raw).to_s).to eq(raw)
    end

    it 'raises InvalidSpiffeIdError for a nil input' do
      expect { described_class.parse_id(nil) }.to raise_error(Legion::Crypt::Spiffe::InvalidSpiffeIdError, /non-empty string/)
    end

    it 'raises InvalidSpiffeIdError for an empty string' do
      expect { described_class.parse_id('') }.to raise_error(Legion::Crypt::Spiffe::InvalidSpiffeIdError, /non-empty string/)
    end

    it 'raises InvalidSpiffeIdError when scheme is not spiffe' do
      expect { described_class.parse_id('https://example.org/foo') }
        .to raise_error(Legion::Crypt::Spiffe::InvalidSpiffeIdError, /scheme/)
    end

    it 'raises InvalidSpiffeIdError when trust domain is missing' do
      expect { described_class.parse_id('spiffe:///workload/foo') }
        .to raise_error(Legion::Crypt::Spiffe::InvalidSpiffeIdError, /trust domain/)
    end

    it 'raises InvalidSpiffeIdError when a query string is present' do
      expect { described_class.parse_id('spiffe://example.org/foo?bar=1') }
        .to raise_error(Legion::Crypt::Spiffe::InvalidSpiffeIdError, /query/)
    end

    it 'raises InvalidSpiffeIdError when a fragment is present' do
      expect { described_class.parse_id('spiffe://example.org/foo#section') }
        .to raise_error(Legion::Crypt::Spiffe::InvalidSpiffeIdError, /fragment/)
    end
  end

  describe '.valid_id?' do
    it 'returns true for a well-formed SPIFFE ID' do
      expect(described_class.valid_id?('spiffe://example.org/workload')).to be true
    end

    it 'returns false for an invalid SPIFFE ID' do
      expect(described_class.valid_id?('http://example.org/workload')).to be false
    end

    it 'returns false for nil' do
      expect(described_class.valid_id?(nil)).to be false
    end
  end

  describe '.enabled?' do
    context 'when Legion::Settings is not defined' do
      before { hide_const('Legion::Settings') }

      it 'returns false' do
        expect(described_class.enabled?).to be false
      end
    end

    context 'when security settings are nil' do
      before do
        stub_const('Legion::Settings', Module.new)
        allow(Legion::Settings).to receive(:[]).with(:security).and_return(nil)
      end

      it 'returns false' do
        expect(described_class.enabled?).to be false
      end
    end

    context 'when spiffe.enabled is false' do
      before do
        stub_const('Legion::Settings', Module.new)
        allow(Legion::Settings).to receive(:[]).with(:security).and_return(
          { spiffe: { enabled: false } }
        )
      end

      it 'returns false' do
        expect(described_class.enabled?).to be false
      end
    end

    context 'when spiffe.enabled is true' do
      before do
        stub_const('Legion::Settings', Module.new)
        allow(Legion::Settings).to receive(:[]).with(:security).and_return(
          { spiffe: { enabled: true, socket_path: '/tmp/spire.sock', trust_domain: 'test.local' } }
        )
      end

      it 'returns true' do
        expect(described_class.enabled?).to be true
      end
    end
  end

  describe '.socket_path' do
    it 'returns the default when settings are absent' do
      hide_const('Legion::Settings')
      expect(described_class.socket_path).to eq('/tmp/spire-agent/public/api.sock')
    end

    it 'reads from settings when present' do
      stub_const('Legion::Settings', Module.new)
      allow(Legion::Settings).to receive(:[]).with(:security).and_return(
        { spiffe: { enabled: true, socket_path: '/var/run/spire.sock' } }
      )
      expect(described_class.socket_path).to eq('/var/run/spire.sock')
    end
  end

  describe '.trust_domain' do
    it 'returns the default when settings are absent' do
      hide_const('Legion::Settings')
      expect(described_class.trust_domain).to eq('legion.internal')
    end

    it 'reads from settings when present' do
      stub_const('Legion::Settings', Module.new)
      allow(Legion::Settings).to receive(:[]).with(:security).and_return(
        { spiffe: { trust_domain: 'corp.example.com' } }
      )
      expect(described_class.trust_domain).to eq('corp.example.com')
    end
  end

  describe '.allow_x509_fallback?' do
    it 'returns false by default when settings are absent' do
      hide_const('Legion::Settings')
      expect(described_class.allow_x509_fallback?).to be false
    end

    it 'reads the fallback flag from settings when present' do
      stub_const('Legion::Settings', Module.new)
      allow(Legion::Settings).to receive(:[]).with(:security).and_return(
        { spiffe: { allow_x509_fallback: true } }
      )
      expect(described_class.allow_x509_fallback?).to be true
    end
  end

  describe 'SpiffeId' do
    let(:id) { described_class.parse_id('spiffe://example.org/ns/prod/sa/worker') }

    it 'exposes trust_domain' do
      expect(id.trust_domain).to eq('example.org')
    end

    it 'exposes path' do
      expect(id.path).to eq('/ns/prod/sa/worker')
    end

    it 'compares equal to an identical SpiffeId' do
      other = described_class.parse_id('spiffe://example.org/ns/prod/sa/worker')
      expect(id).to eq(other)
    end

    it 'does not equal a SpiffeId with a different path' do
      other = described_class.parse_id('spiffe://example.org/ns/prod/sa/other')
      expect(id).not_to eq(other)
    end
  end

  describe 'X509Svid' do
    let(:future) { Time.now + 3600 }
    let(:past)   { Time.now - 1 }

    it 'reports valid? true when cert, key, and expiry are set' do
      svid = Legion::Crypt::Spiffe::X509Svid.new('id', 'cert', 'key', nil, future)
      expect(svid.valid?).to be true
    end

    it 'reports expired? false when expiry is in the future' do
      svid = Legion::Crypt::Spiffe::X509Svid.new('id', 'cert', 'key', nil, future)
      expect(svid.expired?).to be false
    end

    it 'reports expired? true when expiry is in the past' do
      svid = Legion::Crypt::Spiffe::X509Svid.new('id', 'cert', 'key', nil, past)
      expect(svid.expired?).to be true
    end

    it 'reports valid? false when expired' do
      svid = Legion::Crypt::Spiffe::X509Svid.new('id', 'cert', 'key', nil, past)
      expect(svid.valid?).to be false
    end

    it 'returns a positive ttl for a future expiry' do
      svid = Legion::Crypt::Spiffe::X509Svid.new('id', 'cert', 'key', nil, future)
      expect(svid.ttl).to be_positive
    end
  end

  describe 'JwtSvid' do
    let(:future) { Time.now + 3600 }
    let(:past)   { Time.now - 1 }

    it 'reports valid? true when token is set and not expired' do
      svid = Legion::Crypt::Spiffe::JwtSvid.new('id', 'tok', 'aud', future)
      expect(svid.valid?).to be true
    end

    it 'reports expired? true when expiry is in the past' do
      svid = Legion::Crypt::Spiffe::JwtSvid.new('id', 'tok', 'aud', past)
      expect(svid.expired?).to be true
    end
  end
end
