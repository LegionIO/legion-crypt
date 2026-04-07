# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/jwt'

RSpec.describe Legion::Crypt::JWT do
  let(:signing_key) { SecureRandom.hex(32) }
  let(:rsa_private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:rsa_public_key) { rsa_private_key.public_key }
  let(:payload) { { node_id: 'test-node-001', extensions: %w[lex-redis lex-http] } }

  describe '.issue' do
    it 'returns a JWT string' do
      token = described_class.issue(payload, signing_key: signing_key)
      expect(token).to be_a(String)
      expect(token.split('.').length).to eq(3)
    end

    it 'includes standard claims' do
      token = described_class.issue(payload, signing_key: signing_key, ttl: 3600)
      decoded = described_class.decode(token)

      expect(decoded[:iss]).to eq('legion')
      expect(decoded[:iat]).to be_a(Integer)
      expect(decoded[:exp]).to eq(decoded[:iat] + 3600)
      expect(decoded[:jti]).to be_a(String)
    end

    it 'includes custom payload' do
      token = described_class.issue(payload, signing_key: signing_key)
      decoded = described_class.decode(token)

      expect(decoded[:node_id]).to eq('test-node-001')
      expect(decoded[:extensions]).to eq(%w[lex-redis lex-http])
    end

    it 'uses custom issuer' do
      token = described_class.issue(payload, signing_key: signing_key, issuer: 'legion-test')
      decoded = described_class.decode(token)
      expect(decoded[:iss]).to eq('legion-test')
    end

    it 'uses custom ttl' do
      token = described_class.issue(payload, signing_key: signing_key, ttl: 60)
      decoded = described_class.decode(token)
      expect(decoded[:exp] - decoded[:iat]).to eq(60)
    end

    it 'issues HS256 tokens by default' do
      token = described_class.issue(payload, signing_key: signing_key)
      _payload, header = JWT.decode(token, signing_key, true, algorithm: 'HS256')
      expect(header['alg']).to eq('HS256')
    end

    it 'issues RS256 tokens with RSA key' do
      token = described_class.issue(payload, signing_key: rsa_private_key, algorithm: 'RS256')
      _payload, header = JWT.decode(token, rsa_public_key, true, algorithm: 'RS256')
      expect(header['alg']).to eq('RS256')
    end

    it 'raises on unsupported algorithm' do
      expect do
        described_class.issue(payload, signing_key: signing_key, algorithm: 'none')
      end.to raise_error(ArgumentError, /unsupported algorithm/)
    end

    it 'generates unique jti for each token' do
      token1 = described_class.issue(payload, signing_key: signing_key)
      token2 = described_class.issue(payload, signing_key: signing_key)
      decoded1 = described_class.decode(token1)
      decoded2 = described_class.decode(token2)
      expect(decoded1[:jti]).not_to eq(decoded2[:jti])
    end

    it 'does not allow payload to override reserved claims' do
      token = described_class.issue(
        payload.merge('iss' => 'forged', exp: 1, iat: 2, 'jti' => 'fixed-id'),
        signing_key: signing_key,
        issuer:      'legion-secure',
        ttl:         120
      )
      decoded = described_class.decode(token)

      expect(decoded[:iss]).to eq('legion-secure')
      expect(decoded[:jti]).not_to eq('fixed-id')
      expect(decoded[:exp]).to eq(decoded[:iat] + 120)
    end
  end

  describe '.issue_identity_token' do
    let(:identity_hash) do
      {
        id:             'identity-123',
        canonical_name: 'agent@example.com',
        kind:           :service,
        mode:           :automated,
        groups:         (1..55).map { |i| "group-#{i}" }
      }
    end
    let(:identity_resolved) { true }

    before do
      stub_const(
        'Legion::Identity::Process',
        Module.new do
          class << self
            attr_accessor :identity_hash, :resolved
          end

          def self.resolved?
            resolved
          end
        end
      )

      Legion::Identity::Process.identity_hash = identity_hash
      Legion::Identity::Process.resolved = identity_resolved
    end

    it 'issues a token with immutable identity claims and preserves extra claims' do
      token = described_class.issue_identity_token(
        signing_key:  signing_key,
        extra_claims: {
          sub:    'override-me',
          groups: %w[override],
          role:   'worker'
        },
        ttl:          120
      )

      decoded = described_class.decode(token)

      expect(decoded[:sub]).to eq('agent@example.com')
      expect(decoded[:principal_id]).to eq('identity-123')
      expect(decoded[:canonical_name]).to eq('agent@example.com')
      expect(decoded[:kind]).to eq('service')
      expect(decoded[:mode]).to eq('automated')
      expect(decoded[:groups]).to eq(identity_hash[:groups].first(50))
      expect(decoded[:role]).to eq('worker')
    end

    it 'passes issuer kwarg through to JWT.issue' do
      token = described_class.issue_identity_token(signing_key: signing_key, issuer: 'my-cluster')
      decoded = described_class.decode(token)
      expect(decoded[:iss]).to eq('my-cluster')
    end

    it 'defaults issuer to legion' do
      token = described_class.issue_identity_token(signing_key: signing_key)
      decoded = described_class.decode(token)
      expect(decoded[:iss]).to eq('legion')
    end

    it 'prevents extra_claims from overriding identity fields via string keys' do
      token = described_class.issue_identity_token(
        signing_key:  signing_key,
        extra_claims: { 'sub' => 'evil', 'canonical_name' => 'forged' }
      )
      decoded = described_class.decode(token)
      expect(decoded[:sub]).to eq('agent@example.com')
      expect(decoded[:canonical_name]).to eq('agent@example.com')
    end

    it 'merges non-conflicting extra_claims into token' do
      token = described_class.issue_identity_token(
        signing_key:  signing_key,
        extra_claims: { tenant_id: 'acme', role: 'agent' }
      )
      decoded = described_class.decode(token)
      expect(decoded[:tenant_id]).to eq('acme')
      expect(decoded[:role]).to eq('agent')
    end

    it 'caps groups at 50 entries' do
      token = described_class.issue_identity_token(signing_key: signing_key)
      decoded = described_class.decode(token)
      expect(decoded[:groups].length).to eq(50)
    end

    it 'handles nil groups gracefully' do
      Legion::Identity::Process.identity_hash = identity_hash.merge(groups: nil)
      token = described_class.issue_identity_token(signing_key: signing_key)
      decoded = described_class.decode(token)
      expect(decoded[:groups]).to eq([])
    end

    it 'raises ArgumentError when Identity::Process is not defined' do
      hide_const('Legion::Identity::Process')
      expect do
        described_class.issue_identity_token(signing_key: signing_key)
      end.to raise_error(ArgumentError, /Identity::Process not resolved/)
    end

    context 'when identity process is not resolved' do
      let(:identity_resolved) { false }

      it 'raises an error' do
        expect do
          described_class.issue_identity_token(signing_key: signing_key)
        end.to raise_error(ArgumentError, /Identity::Process not resolved/)
      end
    end
  end

  describe '.verify' do
    it 'verifies a valid HS256 token' do
      token = described_class.issue(payload, signing_key: signing_key)
      result = described_class.verify(token, verification_key: signing_key)

      expect(result[:node_id]).to eq('test-node-001')
      expect(result[:iss]).to eq('legion')
    end

    it 'verifies a valid RS256 token' do
      token = described_class.issue(payload, signing_key: rsa_private_key, algorithm: 'RS256')
      result = described_class.verify(token, verification_key: rsa_public_key, algorithm: 'RS256')

      expect(result[:node_id]).to eq('test-node-001')
    end

    it 'raises ExpiredTokenError for expired tokens' do
      token = described_class.issue(payload, signing_key: signing_key, ttl: -1)

      expect do
        described_class.verify(token, verification_key: signing_key)
      end.to raise_error(Legion::Crypt::JWT::ExpiredTokenError, /expired/)
    end

    it 'raises InvalidTokenError for wrong key' do
      token = described_class.issue(payload, signing_key: signing_key)
      wrong_key = SecureRandom.hex(32)

      expect do
        described_class.verify(token, verification_key: wrong_key)
      end.to raise_error(Legion::Crypt::JWT::InvalidTokenError, /verification failed/)
    end

    it 'raises InvalidTokenError for tampered token' do
      token = described_class.issue(payload, signing_key: signing_key)
      parts = token.split('.')
      parts[1] = Base64.urlsafe_encode64('{"node_id":"hacked"}', padding: false)
      tampered = parts.join('.')

      expect do
        described_class.verify(tampered, verification_key: signing_key)
      end.to raise_error(Legion::Crypt::JWT::InvalidTokenError)
    end

    it 'raises DecodeError for malformed token' do
      expect do
        described_class.verify('not.a.jwt', verification_key: signing_key)
      end.to raise_error(Legion::Crypt::JWT::DecodeError)
    end

    it 'skips expiration check when disabled' do
      token = described_class.issue(payload, signing_key: signing_key, ttl: -1)

      result = described_class.verify(token, verification_key: signing_key, verify_expiration: false)
      expect(result[:node_id]).to eq('test-node-001')
    end

    it 'skips issuer check when disabled' do
      token = described_class.issue(payload, signing_key: signing_key, issuer: 'other')

      result = described_class.verify(token, verification_key: signing_key, verify_issuer: false)
      expect(result[:node_id]).to eq('test-node-001')
    end

    it 'raises on algorithm mismatch' do
      token = described_class.issue(payload, signing_key: signing_key, algorithm: 'HS256')

      expect do
        described_class.verify(token, verification_key: rsa_public_key, algorithm: 'RS256')
      end.to raise_error(Legion::Crypt::JWT::InvalidTokenError)
    end
  end

  describe '.decode' do
    it 'decodes without verification' do
      token = described_class.issue(payload, signing_key: signing_key)
      result = described_class.decode(token)

      expect(result[:node_id]).to eq('test-node-001')
      expect(result[:iss]).to eq('legion')
    end

    it 'decodes expired tokens without error' do
      token = described_class.issue(payload, signing_key: signing_key, ttl: -1)
      result = described_class.decode(token)
      expect(result[:node_id]).to eq('test-node-001')
    end

    it 'returns symbolized keys' do
      token = described_class.issue({ 'string_key' => 'value' }, signing_key: signing_key)
      result = described_class.decode(token)
      expect(result).to have_key(:string_key)
    end

    it 'raises DecodeError for garbage input' do
      expect do
        described_class.decode('completely-invalid')
      end.to raise_error(Legion::Crypt::JWT::DecodeError)
    end
  end

  describe '.verify_with_jwks' do
    let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:kid) { 'test-kid-1' }
    let(:jwks_url) { 'https://login.microsoftonline.com/test/discovery/v2.0/keys' }

    let(:token) do
      payload = { sub: 'worker-1', iss: 'https://login.microsoftonline.com/test/v2.0',
                  aud: 'app-client-id', iat: Time.now.to_i, exp: Time.now.to_i + 3600 }
      header = { kid: kid, alg: 'RS256' }
      JWT.encode(payload, rsa_key, 'RS256', header)
    end

    before do
      allow(Legion::Crypt::JwksClient).to receive(:find_key)
        .with(jwks_url, kid).and_return(rsa_key.public_key)
    end

    it 'verifies a valid token' do
      result = described_class.verify_with_jwks(
        token,
        jwks_url: jwks_url,
        issuers:  ['https://login.microsoftonline.com/test/v2.0'],
        audience: 'app-client-id'
      )
      expect(result[:sub]).to eq('worker-1')
    end

    it 'requires issuers to be provided' do
      expect do
        described_class.verify_with_jwks(token, jwks_url: jwks_url, audience: 'app-client-id')
      end.to raise_error(ArgumentError, /issuers is required/)
    end

    it 'requires audience to be provided' do
      expect do
        described_class.verify_with_jwks(
          token,
          jwks_url: jwks_url,
          issuers:  ['https://login.microsoftonline.com/test/v2.0']
        )
      end.to raise_error(ArgumentError, /audience is required/)
    end

    it 'validates issuer when issuers provided' do
      result = described_class.verify_with_jwks(
        token,
        jwks_url: jwks_url,
        issuers:  ['https://login.microsoftonline.com/test/v2.0'],
        audience: 'app-client-id'
      )
      expect(result[:sub]).to eq('worker-1')
    end

    it 'rejects wrong issuer' do
      expect do
        described_class.verify_with_jwks(
          token,
          jwks_url: jwks_url,
          issuers:  ['https://other.issuer.com'],
          audience: 'app-client-id'
        )
      end.to raise_error(Legion::Crypt::JWT::InvalidTokenError, /issuer not allowed/)
    end

    it 'validates audience when provided' do
      result = described_class.verify_with_jwks(
        token,
        jwks_url: jwks_url,
        issuers:  ['https://login.microsoftonline.com/test/v2.0'],
        audience: 'app-client-id'
      )
      expect(result[:sub]).to eq('worker-1')
    end

    it 'rejects wrong audience' do
      expect do
        described_class.verify_with_jwks(
          token,
          jwks_url: jwks_url,
          issuers:  ['https://login.microsoftonline.com/test/v2.0'],
          audience: 'wrong-audience'
        )
      end.to raise_error(Legion::Crypt::JWT::InvalidTokenError, /audience mismatch/)
    end

    it 'rejects expired token' do
      expired_payload = { sub: 'worker-1', iat: Time.now.to_i - 7200, exp: Time.now.to_i - 3600 }
      expired_token = JWT.encode(expired_payload, rsa_key, 'RS256', { kid: kid, alg: 'RS256' })

      expect do
        described_class.verify_with_jwks(
          expired_token,
          jwks_url: jwks_url,
          issuers:  ['https://login.microsoftonline.com/test/v2.0'],
          audience: 'app-client-id'
        )
      end.to raise_error(Legion::Crypt::JWT::ExpiredTokenError)
    end

    it 'rejects token with missing kid' do
      no_kid_token = JWT.encode({ sub: 'test' }, rsa_key, 'RS256')

      expect do
        described_class.verify_with_jwks(
          no_kid_token,
          jwks_url: jwks_url,
          issuers:  ['https://login.microsoftonline.com/test/v2.0'],
          audience: 'app-client-id'
        )
      end.to raise_error(Legion::Crypt::JWT::InvalidTokenError, /missing kid/)
    end

    it 'rejects token signed with wrong key' do
      other_key = OpenSSL::PKey::RSA.generate(2048)
      bad_token = JWT.encode({ sub: 'test', exp: Time.now.to_i + 3600 }, other_key, 'RS256',
                             { kid: kid, alg: 'RS256' })

      expect do
        described_class.verify_with_jwks(
          bad_token,
          jwks_url: jwks_url,
          issuers:  ['https://login.microsoftonline.com/test/v2.0'],
          audience: 'app-client-id'
        )
      end.to raise_error(Legion::Crypt::JWT::InvalidTokenError, /signature verification failed/)
    end
  end

  describe '.decode_header' do
    let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }

    it 'extracts header fields from a JWT' do
      token = JWT.encode({ sub: 'test' }, rsa_key, 'RS256', { kid: 'k1', alg: 'RS256' })
      header = described_class.send(:decode_header, token)
      expect(header['kid']).to eq('k1')
      expect(header['alg']).to eq('RS256')
    end

    it 'raises on invalid token format' do
      expect { described_class.send(:decode_header, 'not.a.valid.token.format') }
        .to raise_error(Legion::Crypt::JWT::DecodeError)
    end
  end

  describe 'error hierarchy' do
    it 'all errors inherit from Legion::Crypt::JWT::Error' do
      expect(Legion::Crypt::JWT::ExpiredTokenError.ancestors).to include(Legion::Crypt::JWT::Error)
      expect(Legion::Crypt::JWT::InvalidTokenError.ancestors).to include(Legion::Crypt::JWT::Error)
      expect(Legion::Crypt::JWT::DecodeError.ancestors).to include(Legion::Crypt::JWT::Error)
    end

    it 'Legion::Crypt::JWT::Error inherits from StandardError' do
      expect(Legion::Crypt::JWT::Error.ancestors).to include(StandardError)
    end
  end

  describe 'SUPPORTED_ALGORITHMS' do
    it 'includes HS256 and RS256' do
      expect(described_class::SUPPORTED_ALGORITHMS).to contain_exactly('HS256', 'RS256')
    end
  end

  describe 'round-trip' do
    it 'HS256 issue -> verify preserves all claims' do
      original = { node_id: 'round-trip', count: 42, nested: { key: 'value' } }
      token = described_class.issue(original, signing_key: signing_key, ttl: 300)
      result = described_class.verify(token, verification_key: signing_key)

      expect(result[:node_id]).to eq('round-trip')
      expect(result[:count]).to eq(42)
      expect(result[:nested]).to eq({ 'key' => 'value' })
    end

    it 'RS256 issue -> verify preserves all claims' do
      original = { node_id: 'rs256-trip', role: 'worker' }
      token = described_class.issue(original, signing_key: rsa_private_key, algorithm: 'RS256')
      result = described_class.verify(token, verification_key: rsa_public_key, algorithm: 'RS256')

      expect(result[:node_id]).to eq('rs256-trip')
      expect(result[:role]).to eq('worker')
    end
  end
end
