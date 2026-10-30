# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_kerberos_auth'

RSpec.describe Legion::Crypt::VaultKerberosAuth do
  let(:spnego_token) { 'fake-spnego-base64' }
  let(:vault_token) { 'hvs.kerberos-token' }
  let(:stubs) { Faraday::Adapter::Test::Stubs.new }
  let(:connection) { Faraday.new { |builder| builder.adapter :test, stubs } }
  let(:config) do
    { protocol: 'http', address: 'vault.example', port: 8200, token: 'old-token',
      vault_namespace: 'team', connected: true, clusters: {} }
  end
  let(:auth_body) do
    Legion::JSON.dump(auth: { client_token: vault_token, lease_duration: 3600, renewable: true,
                              policies: %w[default legion-worker], metadata: { username: 'miverso2' } })
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
    it 'authenticates using a Negotiate header and an empty JSON body in the target namespace' do
      stubs.put('/v1/auth/custom-kerberos/login') do |env|
        expect(env.body).to eq('{}')
        expect(env.request_headers['Authorization']).to eq("Negotiate #{spnego_token}")
        expect(env.request_headers['X-Vault-Namespace']).to eq('team')
        [200, { 'Content-Type' => 'application/json' }, auth_body]
      end

      result = described_class.login(spnego_token: spnego_token, auth_path: 'auth/custom-kerberos/login')

      expect(result).to eq(token: vault_token, lease_duration: 3600, renewable: true,
                           policies: %w[default legion-worker], metadata: { username: 'miverso2' })
      expect(Legion::Crypt.vault_client.token).to eq('old-token')
      expect(Legion::Crypt.vault_client.namespace).to eq('team')
    end

    it 'authenticates against root only when the configured namespace is nil' do
      config[:vault_namespace] = nil
      stubs.put('/v1/auth/kerberos/login') do |env|
        expect(env.request_headers['X-Vault-Namespace']).to be_nil
        expect(env.request_headers['Authorization']).to eq("Negotiate #{spnego_token}")
        [200, {}, auth_body]
      end

      expect(described_class.login(spnego_token: spnego_token)).to include(token: vault_token)
      expect(Legion::Crypt.vault_client.namespace).to be_nil
    end

    it 'rejects authentication when Vault is unavailable' do
      allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)

      expect { described_class.login(spnego_token: spnego_token) }.to raise_error(described_class::AuthError)
    end

    it 'rejects a response without an authentication grant' do
      stubs.put('/v1/auth/kerberos/login') { [200, {}, Legion::JSON.dump(data: {})] }

      expect { described_class.login(spnego_token: spnego_token) }.to raise_error(described_class::AuthError)
    end

    it 'rejects an empty successful response' do
      stubs.put('/v1/auth/kerberos/login') { [204, {}, ''] }

      expect { described_class.login(spnego_token: spnego_token) }.to raise_error(described_class::AuthError)
    end

    it 'maps authorization failures to AuthError without changing the namespace' do
      stubs.put('/v1/auth/kerberos/login') { [403, {}, Legion::JSON.dump(errors: ['permission denied'])] }

      expect { described_class.login(spnego_token: spnego_token) }
        .to raise_error(described_class::AuthError, /permission denied/)
      expect(Legion::Crypt.vault_client.namespace).to eq('team')
    end

    it 'preserves server errors and their HTTP status for callers' do
      stubs.put('/v1/auth/kerberos/login') { [503, {}, Legion::JSON.dump(errors: ['sealed'])] }

      expect { described_class.login(spnego_token: spnego_token) }
        .to raise_error(Legion::Crypt::Vault::HTTPServerError) { |error| expect(error.code).to eq(503) }
    end
  end

  describe '.login!' do
    before do
      stubs.put('/v1/auth/kerberos/login') { [200, {}, auth_body] }
      stubs.put('/v1/auth/token/revoke-self') { [204, {}, nil] }
    end

    it 'keeps the new token in config and on the selected cached client for subsequent requests' do
      client = Legion::Crypt.vault_client
      described_class.login!(spnego_token: spnego_token)

      expect(config[:token]).to eq(vault_token)
      expect(Legion::Crypt.vault_client).to equal(client)
      expect(client.token).to eq(vault_token)
      stubs.get('/v1/secret/data/protected') do |env|
        expect(env.request_headers['X-Vault-Token']).to eq(vault_token)
        [200, {}, Legion::JSON.dump(data: { authorized: true })]
      end
      expect(Legion::Crypt.vault_client.logical.read(path: 'secret/data/protected').data).to eq(authorized: true)
    end

    it 'updates the selected cluster without overwriting unrelated tokens' do
      selected = { protocol: 'http', address: 'vault.example', port: 8200, token: 'cluster-old', namespace: 'team',
                   lease_duration: 1, renewable: false, expires_at: Time.now + 1, relogin_required: true }
      config[:clusters] = { primary: selected, secondary: selected.merge(token: 'other-token') }
      config[:default] = :primary
      client = Legion::Crypt.vault_client

      described_class.login!(spnego_token: spnego_token)

      expect(selected[:token]).to eq(vault_token)
      expect(config[:token]).to eq('old-token')
      expect(config[:clusters][:secondary][:token]).to eq('other-token')
      expect(Legion::Crypt.vault_client).to equal(client)
      expect(client.token).to eq(vault_token)
      expect(selected[:expires_at]).to be > Time.now + 3500
      expect(selected[:renewable]).to be(true)
      expect(Legion::Crypt.connected_clusters).to have_key(:primary)
    end

    it 'does not replace credentials when authentication fails' do
      allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)
      client = Legion::Crypt.vault_client

      expect { described_class.login!(spnego_token: spnego_token) }.to raise_error(described_class::AuthError)
      expect(config[:token]).to eq('old-token')
      expect(client.token).to eq('old-token')
    end
  end
end
