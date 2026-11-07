# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_jwt_auth'

RSpec.describe Legion::Crypt::VaultJwtAuth do
  let(:sample_jwt) { 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3b3JrZXIifQ.sig' }
  let(:vault_token) { 'hvs.jwt-token' }
  let(:stubs) { Faraday::Adapter::Test::Stubs.new }
  let(:connection) { Faraday.new { |builder| builder.adapter :test, stubs } }
  let(:config) do
    Legion::Crypt::Settings.vault.merge(
      protocol: 'http', address: 'vault.example', port: 8200, token: 'old-token',
      vault_namespace: 'team', connected: true, clusters: {}
    )
  end
  let(:auth_body) do
    Legion::JSON.dump(auth: { client_token: vault_token, lease_duration: 3600, renewable: true,
                              policies: %w[default legion-worker], metadata: { worker_id: 'abc-123' } })
  end

  before do
    @original_vault = Legion::Settings[:crypt][:vault]
    Legion::Settings[:crypt][:vault] = config
    Legion::Crypt.clear_vault_clients
    connection
    allow(Faraday).to receive(:new).and_return(connection)
    allow(Legion::Crypt).to receive(:vault_connected?).and_return(true)
  end

  after do
    Legion::Crypt.shutdown
    Legion::Settings[:crypt][:vault] = @original_vault
  end

  describe '.login' do
    it 'authenticates in the configured namespace and decodes the Vault grant' do
      stubs.put('/v1/auth/oidc/login') do |env|
        expect(Legion::JSON.load(env.body)).to eq(role: 'custom-worker', jwt: sample_jwt)
        expect(env.request_headers['X-Vault-Namespace']).to eq('team')
        [200, { 'Content-Type' => 'application/json' }, auth_body]
      end

      result = described_class.login(jwt: sample_jwt, role: 'custom-worker', auth_path: 'auth/oidc/login')

      expect(result).to eq(token: vault_token, lease_duration: 3600, renewable: true,
                           policies: %w[default legion-worker], metadata: { worker_id: 'abc-123' })
      expect(Legion::Crypt.vault_client.token).to eq('old-token')
    end

    it 'rejects authentication when Vault is unavailable' do
      allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)

      expect { described_class.login(jwt: sample_jwt) }.to raise_error(described_class::AuthError)
    end

    it 'rejects a successful response without an auth grant' do
      stubs.put('/v1/auth/jwt/login') { [200, {}, Legion::JSON.dump(data: {})] }

      expect { described_class.login(jwt: sample_jwt) }.to raise_error(described_class::AuthError)
    end

    it 'rejects an empty successful response' do
      stubs.put('/v1/auth/jwt/login') { [204, {}, ''] }

      expect { described_class.login(jwt: sample_jwt) }.to raise_error(described_class::AuthError)
    end

    it 'maps a rejected JWT to AuthError and retains the server reason' do
      stubs.put('/v1/auth/jwt/login') { [403, {}, Legion::JSON.dump(errors: ['permission denied'])] }

      expect { described_class.login(jwt: sample_jwt) }
        .to raise_error(described_class::AuthError, /permission denied/)
    end

    it 'maps Vault server failures to AuthError' do
      stubs.put('/v1/auth/jwt/login') { [503, {}, Legion::JSON.dump(errors: ['temporarily unavailable'])] }

      expect { described_class.login(jwt: sample_jwt) }
        .to raise_error(described_class::AuthError, /temporarily unavailable/)
    end
  end

  describe '.login!' do
    before do
      stubs.put('/v1/auth/jwt/login') { [200, {}, auth_body] }
    end

    it 'keeps the authenticated client and top-level config synchronized across cache lookups' do
      client = Legion::Crypt.vault_client
      described_class.login!(jwt: sample_jwt)

      expect(config[:token]).to eq(vault_token)
      expect(Legion::Crypt.vault_client).to equal(client)
      expect(client.token).to eq(vault_token)
      stubs.get('/v1/secret/data/protected') do |env|
        expect(env.request_headers['X-Vault-Token']).to eq(vault_token)
        [200, {}, Legion::JSON.dump(data: { authorized: true })]
      end
      expect(Legion::Crypt.vault_client.logical.read(path: 'secret/data/protected').data).to eq(authorized: true)
    end

    it 'updates only the selected cluster token without replacing its cached client' do
      selected = { protocol: 'http', address: 'vault.example', port: 8200, token: 'cluster-old', namespace: 'team' }
      config[:clusters] = { primary: selected, secondary: selected.merge(token: 'other-token') }
      config[:default] = :primary
      client = Legion::Crypt.vault_client

      described_class.login!(jwt: sample_jwt)

      expect(selected[:token]).to eq(vault_token)
      expect(config[:token]).to eq('old-token')
      expect(config[:clusters][:secondary][:token]).to eq('other-token')
      expect(Legion::Crypt.vault_client).to equal(client)
      expect(client.token).to eq(vault_token)
    end

    it 'replaces the old grant lifetime and worker rather than expiring a newly authenticated token' do
      selected = { protocol: 'http', address: 'vault.example', port: 8200, namespace: 'team', auth_method: 'ldap' }
      config.merge!(clusters: { primary: selected }, default: :primary)
      allow(Legion::Crypt).to receive(:vault_connected?).and_call_original
      stubs.put('/v1/auth/ldap/login/test-user') do
        [200, {}, Legion::JSON.dump({ auth: { client_token: 'old-ldap', lease_duration: 0.05,
                                             renewable: false, policies: [] } })]
      end
      Legion::Crypt.ldap_login(cluster_name: :primary, username: 'test-user', password: 'fixture-password')
      old_expiry = selected[:expires_at]
      described_class.login!(jwt: sample_jwt)
      sleep([old_expiry - Time.now + 0.02, 0].max)
      stubs.get('/v1/secret/protected') do |request|
        expect(request.request_headers['X-Vault-Token']).to eq(vault_token)
        [200, {}, Legion::JSON.dump({ data: { authorized: true } })]
      end

      expect(Legion::Crypt.vault_connected?).to be(true)
      expect(Legion::Crypt.read('secret/protected')).to eq(authorized: true)
      expect(selected[:expires_at]).to be > Time.now + 3500
      expect(selected[:renewable]).to be(true)
      expect(selected[:auth_method]).to eq('jwt')
    end

    it 'leaves the current token intact when authentication is rejected' do
      allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)
      client = Legion::Crypt.vault_client

      expect { described_class.login!(jwt: sample_jwt) }.to raise_error(described_class::AuthError)
      expect(config[:token]).to eq('old-token')
      expect(client.token).to eq('old-token')
    end
  end

  describe '.worker_login' do
    it 'presents a verifiable short-lived worker JWT with the requested identity and audience' do
      signing_key = 'a' * 64
      allow(Legion::Crypt).to receive(:cluster_secret).and_return(signing_key)
      stubs.put('/v1/auth/jwt/login') do |env|
        request = Legion::JSON.load(env.body)
        claims = Legion::Crypt::JWT.verify(request[:jwt], verification_key: signing_key)
        expect(claims).to include(worker_id: 'worker-123', sub: 'user@example.com', scope: 'vault', aud: 'legion', iss: 'legion')
        expect(claims[:exp] - claims[:iat]).to eq(300)
        [200, {}, auth_body]
      end

      expect(described_class.worker_login(worker_id: 'worker-123', owner_msid: 'user@example.com'))
        .to include(token: vault_token)
    end
  end
end
