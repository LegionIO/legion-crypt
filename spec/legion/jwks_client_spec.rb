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
  let(:rotated_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:rotated_response) { { keys: [JWT::JWK.new(rotated_key, kid: 'rotated-kid').export] }.to_json }

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
    it 'coalesces five simultaneous cold misses into one upstream request' do
      body = jwks_response
      requests = Queue.new
      release = Queue.new
      allow(described_class).to receive(:http_get) do
        requests << true
        release.pop
        body
      end
      workers = 5.times.map { Thread.new { described_class.find_key(jwks_url, 'test-kid-1') } }
      Timeout.timeout(3) { Thread.pass until workers.all?(&:stop?) }
      5.times { release << true }
      keys = Timeout.timeout(3) { workers.map(&:value) }

      expect(requests.size).to eq(1)
      expect(keys.map(&:to_der).uniq).to eq([rsa_key.public_key.to_der])
    ensure
      workers&.each(&:kill)
      workers&.each(&:join)
    end

    it 'uses a cached key without contacting the issuer again' do
      allow(described_class).to receive(:http_get).and_return(jwks_response)
      described_class.fetch_keys(jwks_url)
      key = described_class.find_key(jwks_url, 'test-kid-1')
      signature = rsa_key.sign('SHA256', 'cached key')
      expect(key.verify('SHA256', signature, 'cached key')).to be(true)
      expect(described_class).to have_received(:http_get).once
    end

    it 'allows one immediate unknown-key refresh and bounds repeated distinct misses' do
      allow(described_class).to receive(:http_get).and_return(jwks_response)
      described_class.fetch_keys(jwks_url)

      5.times do |index|
        expect { described_class.find_key(jwks_url, "unknown-#{index}") }
          .to raise_error(Legion::Crypt::JWT::InvalidTokenError)
      end
      expect(described_class).to have_received(:http_get).twice
    end

    it 'discovers a rotated key on the first unknown-key refresh' do
      allow(described_class).to receive(:http_get).and_return(jwks_response, rotated_response)
      described_class.fetch_keys(jwks_url)
      key = described_class.find_key(jwks_url, 'rotated-kid')
      expect(key.to_der).to eq(rotated_key.public_key.to_der)
    end

    it 'allows another rotation lookup once the miss cooldown expires' do
      allow(Process).to receive(:clock_gettime).and_call_original
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(100.0)
      allow(described_class).to receive(:http_get).and_return(jwks_response)
      described_class.fetch_keys(jwks_url)
      expect { described_class.find_key(jwks_url, 'rotated-kid') }
        .to raise_error(Legion::Crypt::JWT::InvalidTokenError)

      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC)
                                               .and_return(100.0 + described_class::MISS_REFRESH_COOLDOWN + 1)
      allow(described_class).to receive(:http_get).and_return(rotated_response)
      expect(described_class.find_key(jwks_url, 'rotated-kid').to_der).to eq(rotated_key.public_key.to_der)
    end

    it 'refreshes an expired cache even when the requested key was previously present' do
      now = Time.now
      allow(Time).to receive(:now).and_return(now)
      replacement = { keys: [JWT::JWK.new(rotated_key, kid: 'test-kid-1').export] }.to_json
      allow(described_class).to receive(:http_get).and_return(jwks_response, replacement)
      described_class.fetch_keys(jwks_url)
      allow(Time).to receive(:now).and_return(now + described_class::CACHE_TTL + 1)
      expect(described_class.find_key(jwks_url, 'test-kid-1').to_der).to eq(rotated_key.public_key.to_der)
      expect(described_class).to have_received(:http_get).twice
    end

    it 'shares upstream failures during cooldown rather than repeating failed requests' do
      allow(described_class).to receive(:http_get).and_raise(Legion::Crypt::JWT::Error, 'issuer unavailable')
      5.times do
        expect { described_class.find_key(jwks_url, 'test-kid-1') }.to raise_error(Legion::Crypt::JWT::Error)
      end
      expect(described_class).to have_received(:http_get).once
    end
  end

  describe '.clear_cache' do
    it 'forces the next lookup to load current upstream key material' do
      replacement = { keys: [JWT::JWK.new(rotated_key, kid: 'test-kid-1').export] }.to_json
      allow(described_class).to receive(:http_get).and_return(jwks_response, replacement)
      described_class.fetch_keys(jwks_url)
      described_class.clear_cache
      expect(described_class.find_key(jwks_url, 'test-kid-1').to_der).to eq(rotated_key.public_key.to_der)
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
