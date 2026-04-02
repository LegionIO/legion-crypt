# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/jwks_client'

RSpec.describe Legion::Crypt::JwksClient do
  let(:jwks_url) { 'https://login.microsoftonline.com/test-tenant/discovery/v2.0/keys' }
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:jwk) { JWT::JWK.new(rsa_key, kid: 'test-kid-1') }
  let(:jwks_response) do
    { 'keys' => [jwk.export.transform_keys(&:to_s)] }.to_json
  end

  before { described_class.clear_cache }

  describe '.fetch_keys' do
    it 'fetches and parses JWKS from a URL' do
      allow(described_class).to receive(:http_get).with(jwks_url).and_return(jwks_response)

      keys = described_class.fetch_keys(jwks_url)
      expect(keys).to have_key('test-kid-1')
      expect(keys['test-kid-1']).to be_a(OpenSSL::PKey::RSA)
    end

    it 'raises on HTTP failure' do
      allow(described_class).to receive(:http_get)
        .and_raise(Legion::Crypt::JWT::Error, 'failed to fetch JWKS: HTTP 500')

      expect { described_class.fetch_keys(jwks_url) }
        .to raise_error(Legion::Crypt::JWT::Error, /HTTP 500/)
    end

    it 'raises on invalid JSON' do
      allow(described_class).to receive(:http_get).and_return('not json')

      expect { described_class.fetch_keys(jwks_url) }
        .to raise_error(Legion::Crypt::JWT::Error, /invalid JWKS/)
    end

    it 'raises on missing keys array' do
      allow(described_class).to receive(:http_get).and_return('{}')

      expect { described_class.fetch_keys(jwks_url) }
        .to raise_error(Legion::Crypt::JWT::Error, /missing keys/)
    end

    it 'skips malformed keys without raising' do
      bad_response = { 'keys' => [{ 'kid' => 'bad', 'kty' => 'invalid' }, jwk.export.transform_keys(&:to_s)] }.to_json
      allow(described_class).to receive(:http_get).and_return(bad_response)

      keys = described_class.fetch_keys(jwks_url)
      expect(keys).to have_key('test-kid-1')
      expect(keys).not_to have_key('bad')
    end
  end

  describe '.find_key' do
    context 'with cached keys' do
      before do
        allow(described_class).to receive(:http_get).and_return(jwks_response)
        described_class.fetch_keys(jwks_url)
      end

      it 'returns the key for a known kid' do
        key = described_class.find_key(jwks_url, 'test-kid-1')
        expect(key).to be_a(OpenSSL::PKey::RSA)
      end

      it 'raises for an unknown kid after re-fetch' do
        expect(described_class).not_to receive(:fetch_keys)

        expect { described_class.find_key(jwks_url, 'unknown-kid') }
          .to raise_error(Legion::Crypt::JWT::InvalidTokenError, /signing key not found/)
      end
    end

    context 'with expired cache' do
      before do
        allow(described_class).to receive(:http_get).and_return(jwks_response)
        described_class.fetch_keys(jwks_url)

        # Simulate expiry
        allow(described_class).to receive(:expired?).and_return(true)
      end

      it 're-fetches keys on expiry' do
        expect(described_class).to receive(:fetch_keys).with(jwks_url).and_call_original
        described_class.find_key(jwks_url, 'test-kid-1')
      end
    end

    context 'with no cache' do
      it 'fetches keys on first call' do
        allow(described_class).to receive(:http_get).and_return(jwks_response)

        key = described_class.find_key(jwks_url, 'test-kid-1')
        expect(key).to be_a(OpenSSL::PKey::RSA)
      end
    end
  end

  describe '.clear_cache' do
    it 'empties the cache' do
      allow(described_class).to receive(:http_get).and_return(jwks_response)
      described_class.fetch_keys(jwks_url)

      described_class.clear_cache

      # After clear, find_key must re-fetch
      expect(described_class).to receive(:fetch_keys).with(jwks_url).and_call_original
      described_class.find_key(jwks_url, 'test-kid-1')
    end
  end

  describe '.http_get' do
    it 'rejects non-HTTPS JWKS URLs' do
      expect do
        described_class.send(:http_get, 'http://example.com/keys')
      end.to raise_error(Legion::Crypt::JWT::Error, /HTTPS is required/)
    end
  end
end
