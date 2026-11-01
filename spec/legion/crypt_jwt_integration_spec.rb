# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt'

RSpec.describe 'Legion::Crypt JWT convenience methods' do
  around do |example|
    original = Legion::Settings[:crypt]
    Legion::Settings.set_prop(:crypt, Legion::Crypt::Settings.default.merge(cluster_secret: SecureRandom.hex(32)))
    example.run
  ensure
    Legion::Settings.set_prop(:crypt, original)
  end

  describe '.issue_token' do
    it 'issues an HS256 token using cluster secret' do
      token = Legion::Crypt.issue_token({ node_id: 'test' })
      expect(token).to be_a(String)
      expect(token.split('.').length).to eq(3)
    end

    it 'issues an RS256 token using private key' do
      token = Legion::Crypt.issue_token({ node_id: 'test' }, algorithm: 'RS256')
      expect(token).to be_a(String)

      decoded = Legion::Crypt::JWT.decode(token)
      expect(decoded[:node_id]).to eq('test')
    end

    it 'uses default ttl from settings' do
      token = Legion::Crypt.issue_token({ node_id: 'test' })
      decoded = Legion::Crypt::JWT.decode(token)
      expect(decoded[:exp] - decoded[:iat]).to eq(3600)
    end

    it 'allows overriding ttl' do
      token = Legion::Crypt.issue_token({ node_id: 'test' }, ttl: 120)
      decoded = Legion::Crypt::JWT.decode(token)
      expect(decoded[:exp] - decoded[:iat]).to eq(120)
    end
  end

  describe '.verify_token' do
    it 'verifies an HS256 token' do
      token = Legion::Crypt.issue_token({ node_id: 'verify-test' })
      result = Legion::Crypt.verify_token(token)
      expect(result[:node_id]).to eq('verify-test')
    end

    it 'verifies an RS256 token' do
      token = Legion::Crypt.issue_token({ node_id: 'rs256-test' }, algorithm: 'RS256')
      result = Legion::Crypt.verify_token(token, algorithm: 'RS256')
      expect(result[:node_id]).to eq('rs256-test')
    end

    it 'raises for expired tokens' do
      token = Legion::Crypt.issue_token({ node_id: 'expired' }, ttl: -1)
      expect do
        Legion::Crypt.verify_token(token)
      end.to raise_error(Legion::Crypt::JWT::ExpiredTokenError)
    end

    it 'round-trips correctly' do
      payload = { node_id: 'round-trip', extensions: %w[lex-redis lex-http] }
      token = Legion::Crypt.issue_token(payload)
      result = Legion::Crypt.verify_token(token)
      expect(result[:node_id]).to eq('round-trip')
      expect(result[:extensions]).to eq(%w[lex-redis lex-http])
    end

    it 'honors disabled verification after replacing live JWT configuration' do
      token = Legion::Crypt.issue_token({ node_id: 'expired' }, ttl: -1)
      replacement = Legion::Settings[:crypt].merge(
        jwt: Legion::Settings[:crypt][:jwt].merge(verify_expiration: false, verify_issuer: false, issuer: 'other')
      )
      Legion::Settings.set_prop(:crypt, replacement)
      expect(Legion::Crypt.verify_token(token)[:node_id]).to eq('expired')

      Legion::Settings[:crypt][:jwt][:verify_expiration] = true
      expect { Legion::Crypt.verify_token(token) }.to raise_error(Legion::Crypt::JWT::ExpiredTokenError)
    end
  end
end
