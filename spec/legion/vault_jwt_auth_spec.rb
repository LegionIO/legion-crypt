# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_jwt_auth'

RSpec.describe Legion::Crypt::VaultJwtAuth do
  let(:sample_jwt)    { 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3b3JrZXIifQ.sig' }
  let(:vault_token)   { 'hvs.CAESIJ-sample-vault-token' }
  let(:auth_response) do
    auth = double(
      'VaultAuth',
      client_token:   vault_token,
      lease_duration: 3600,
      renewable?:     true,
      policies:       %w[default legion-worker],
      metadata:       { 'worker_id' => 'abc-123' }
    )
    double('VaultResponse', auth: auth)
  end

  let(:vault_logical) { double('VaultLogical') }

  before do
    @original_connected = Legion::Settings[:crypt][:vault][:connected]
    Legion::Settings[:crypt][:vault][:connected] = true

    stub_const('Vault', Module.new)
    stub_const('Vault::HTTPClientError', Class.new(StandardError))
    stub_const('Vault::HTTPServerError', Class.new(StandardError))
    allow(Vault).to receive(:logical).and_return(vault_logical)
    allow(vault_logical).to receive(:write).and_return(auth_response)
  end

  after do
    Legion::Settings[:crypt][:vault][:connected] = @original_connected
  end

  describe '.login' do
    context 'when Vault is connected and auth succeeds' do
      it 'returns a hash with token and metadata' do
        result = described_class.login(jwt: sample_jwt)

        expect(result).to be_a(Hash)
        expect(result[:token]).to eq(vault_token)
        expect(result[:lease_duration]).to eq(3600)
        expect(result[:renewable]).to eq(true)
        expect(result[:policies]).to eq(%w[default legion-worker])
        expect(result[:metadata]).to eq({ 'worker_id' => 'abc-123' })
      end

      it 'calls Vault.logical.write with the correct auth_path, role, and jwt' do
        expect(vault_logical).to receive(:write).with(
          'auth/jwt/login',
          role: 'legion-worker',
          jwt:  sample_jwt
        ).and_return(auth_response)

        described_class.login(jwt: sample_jwt)
      end

      it 'uses DEFAULT_AUTH_PATH by default' do
        expect(vault_logical).to receive(:write).with(
          Legion::Crypt::VaultJwtAuth::DEFAULT_AUTH_PATH,
          hash_including(jwt: sample_jwt)
        ).and_return(auth_response)

        described_class.login(jwt: sample_jwt)
      end

      it 'uses DEFAULT_ROLE by default' do
        expect(vault_logical).to receive(:write).with(
          anything,
          hash_including(role: Legion::Crypt::VaultJwtAuth::DEFAULT_ROLE)
        ).and_return(auth_response)

        described_class.login(jwt: sample_jwt)
      end

      it 'accepts a custom role' do
        expect(vault_logical).to receive(:write).with(
          anything,
          hash_including(role: 'custom-role')
        ).and_return(auth_response)

        described_class.login(jwt: sample_jwt, role: 'custom-role')
      end

      it 'accepts a custom auth_path' do
        expect(vault_logical).to receive(:write).with(
          'auth/oidc/login',
          anything
        ).and_return(auth_response)

        described_class.login(jwt: sample_jwt, auth_path: 'auth/oidc/login')
      end
    end

    context 'when Vault is not connected' do
      before do
        Legion::Settings[:crypt][:vault][:connected] = false
      end

      it 'raises AuthError' do
        expect do
          described_class.login(jwt: sample_jwt)
        end.to raise_error(Legion::Crypt::VaultJwtAuth::AuthError, 'Vault is not connected')
      end
    end

    context 'when Vault returns a response with no auth data' do
      it 'raises AuthError' do
        allow(vault_logical).to receive(:write).and_return(double('VaultResponse', auth: nil))

        expect do
          described_class.login(jwt: sample_jwt)
        end.to raise_error(Legion::Crypt::VaultJwtAuth::AuthError, 'Vault JWT auth returned no auth data')
      end
    end

    context 'when Vault returns nil response' do
      it 'raises AuthError' do
        allow(vault_logical).to receive(:write).and_return(nil)

        expect do
          described_class.login(jwt: sample_jwt)
        end.to raise_error(Legion::Crypt::VaultJwtAuth::AuthError, 'Vault JWT auth returned no auth data')
      end
    end

    context 'when Vault raises HTTPClientError (4xx)' do
      it 'wraps it in AuthError' do
        allow(vault_logical).to receive(:write).and_raise(Vault::HTTPClientError, 'permission denied')

        expect do
          described_class.login(jwt: sample_jwt)
        end.to raise_error(Legion::Crypt::VaultJwtAuth::AuthError, /Vault JWT auth failed: permission denied/)
      end
    end

    context 'when Vault raises HTTPServerError (5xx)' do
      it 'wraps it in AuthError' do
        allow(vault_logical).to receive(:write).and_raise(Vault::HTTPServerError, 'internal server error')

        expect do
          described_class.login(jwt: sample_jwt)
        end.to raise_error(Legion::Crypt::VaultJwtAuth::AuthError, /Vault server error during JWT auth: internal server error/)
      end
    end
  end

  describe '.login!' do
    before do
      allow(Vault).to receive(:token=)
      allow(Legion::Logging).to receive(:info)
    end

    it 'calls login and returns the same result' do
      result = described_class.login!(jwt: sample_jwt)

      expect(result[:token]).to eq(vault_token)
      expect(result[:policies]).to eq(%w[default legion-worker])
    end

    it 'sets the Vault client token' do
      expect(Vault).to receive(:token=).with(vault_token)

      described_class.login!(jwt: sample_jwt)
    end

    it 'logs the authenticated policies' do
      expect(Legion::Logging).to receive(:info).with(/authenticated via JWT auth.*default,legion-worker/)

      described_class.login!(jwt: sample_jwt)
    end

    it 'propagates AuthError from login' do
      Legion::Settings[:crypt][:vault][:connected] = false

      expect do
        described_class.login!(jwt: sample_jwt)
      end.to raise_error(Legion::Crypt::VaultJwtAuth::AuthError, 'Vault is not connected')
    end

    it 'accepts custom role and auth_path' do
      expect(vault_logical).to receive(:write).with(
        'auth/oidc/login',
        hash_including(role: 'oidc-worker')
      ).and_return(auth_response)

      described_class.login!(jwt: sample_jwt, role: 'oidc-worker', auth_path: 'auth/oidc/login')
    end
  end

  describe '.worker_login' do
    let(:worker_id)   { 'worker-abc-123' }
    let(:owner_msid)  { 'user@example.com' }
    let(:cluster_key) { SecureRandom.hex(32) }
    let(:worker_jwt)  { 'worker.signed.jwt' }

    before do
      allow(Legion::Crypt).to receive(:cluster_secret).and_return(cluster_key)
      allow(Legion::Crypt::JWT).to receive(:issue).and_return(worker_jwt)
      allow(vault_logical).to receive(:write).and_return(auth_response)
    end

    it 'issues a JWT with worker payload' do
      expect(Legion::Crypt::JWT).to receive(:issue).with(
        { worker_id: worker_id, sub: owner_msid, scope: 'vault', aud: 'legion' },
        signing_key: cluster_key,
        ttl:         300,
        issuer:      'legion'
      ).and_return(worker_jwt)

      described_class.worker_login(worker_id: worker_id, owner_msid: owner_msid)
    end

    it 'passes the issued JWT to login' do
      expect(vault_logical).to receive(:write).with(
        'auth/jwt/login',
        hash_including(jwt: worker_jwt, role: 'legion-worker')
      ).and_return(auth_response)

      described_class.worker_login(worker_id: worker_id, owner_msid: owner_msid)
    end

    it 'returns the auth result hash' do
      result = described_class.worker_login(worker_id: worker_id, owner_msid: owner_msid)

      expect(result[:token]).to eq(vault_token)
      expect(result[:lease_duration]).to eq(3600)
    end

    it 'accepts a custom role' do
      expect(vault_logical).to receive(:write).with(
        anything,
        hash_including(role: 'special-worker')
      ).and_return(auth_response)

      described_class.worker_login(worker_id: worker_id, owner_msid: owner_msid, role: 'special-worker')
    end
  end

  describe 'AuthError' do
    it 'inherits from StandardError' do
      expect(Legion::Crypt::VaultJwtAuth::AuthError.ancestors).to include(StandardError)
    end

    it 'carries the error message' do
      err = Legion::Crypt::VaultJwtAuth::AuthError.new('something went wrong')
      expect(err.message).to eq('something went wrong')
    end
  end

  describe 'constants' do
    it 'DEFAULT_AUTH_PATH is auth/jwt/login' do
      expect(described_class::DEFAULT_AUTH_PATH).to eq('auth/jwt/login')
    end

    it 'DEFAULT_ROLE is legion-worker' do
      expect(described_class::DEFAULT_ROLE).to eq('legion-worker')
    end
  end
end
