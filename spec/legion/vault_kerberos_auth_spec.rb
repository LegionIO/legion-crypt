# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_kerberos_auth'

RSpec.describe Legion::Crypt::VaultKerberosAuth do
  let(:spnego_token) { 'fake-spnego-base64' }
  let(:vault_token)  { 'hvs.test-token' }
  let(:auth_double) do
    double('VaultAuth',
           client_token:   vault_token,
           lease_duration: 3600,
           renewable?:     true,
           policies:       %w[default legion-worker],
           metadata:       { 'username' => 'miverso2' })
  end
  let(:response_double) { double('VaultResponse', auth: auth_double) }
  let(:vault_logical)   { double('VaultLogical') }

  before do
    @original_connected = Legion::Settings[:crypt][:vault][:connected]
    Legion::Settings[:crypt][:vault][:connected] = true

    stub_const('Vault', Module.new)
    stub_const('Vault::HTTPClientError', Class.new(StandardError))
    allow(Vault).to receive(:logical).and_return(vault_logical)
    allow(vault_logical).to receive(:write).and_return(response_double)
  end

  after do
    Legion::Settings[:crypt][:vault][:connected] = @original_connected
  end

  describe '.login' do
    context 'when Vault is connected' do
      it 'exchanges a SPNEGO token for a Vault token' do
        result = described_class.login(spnego_token: spnego_token)
        expect(result[:token]).to eq(vault_token)
        expect(result[:policies]).to include('legion-worker')
        expect(result[:lease_duration]).to eq(3600)
        expect(result[:renewable]).to be true
        expect(result[:metadata]).to eq({ 'username' => 'miverso2' })
      end

      it 'calls Vault.logical.write with Negotiate authorization header' do
        expect(vault_logical).to receive(:write).with(
          'auth/kerberos/login',
          authorization: "Negotiate #{spnego_token}"
        ).and_return(response_double)

        described_class.login(spnego_token: spnego_token)
      end

      it 'uses DEFAULT_AUTH_PATH by default' do
        expect(vault_logical).to receive(:write).with(
          Legion::Crypt::VaultKerberosAuth::DEFAULT_AUTH_PATH,
          anything
        ).and_return(response_double)

        described_class.login(spnego_token: spnego_token)
      end
    end

    context 'when Vault is not connected' do
      before do
        Legion::Settings[:crypt][:vault][:connected] = false
      end

      it 'raises AuthError' do
        expect { described_class.login(spnego_token: spnego_token) }
          .to raise_error(Legion::Crypt::VaultKerberosAuth::AuthError, 'Vault is not connected')
      end
    end

    context 'when Vault returns no auth data' do
      it 'raises AuthError' do
        allow(vault_logical).to receive(:write).and_return(double('VaultResponse', auth: nil))

        expect { described_class.login(spnego_token: spnego_token) }
          .to raise_error(Legion::Crypt::VaultKerberosAuth::AuthError, 'Vault Kerberos auth returned no auth data')
      end
    end

    context 'when Vault returns nil response' do
      it 'raises AuthError' do
        allow(vault_logical).to receive(:write).and_return(nil)

        expect { described_class.login(spnego_token: spnego_token) }
          .to raise_error(Legion::Crypt::VaultKerberosAuth::AuthError, 'Vault Kerberos auth returned no auth data')
      end
    end

    context 'when Vault raises HTTPClientError (4xx)' do
      it 'wraps it in AuthError' do
        allow(vault_logical).to receive(:write).and_raise(Vault::HTTPClientError, 'permission denied')

        expect { described_class.login(spnego_token: spnego_token) }
          .to raise_error(Legion::Crypt::VaultKerberosAuth::AuthError, /Vault Kerberos auth failed: permission denied/)
      end
    end

    context 'with custom auth path' do
      it 'uses the custom auth path' do
        expect(vault_logical).to receive(:write).with(
          'auth/custom-kerberos/login',
          authorization: 'Negotiate token123'
        ).and_return(response_double)

        result = described_class.login(spnego_token: 'token123', auth_path: 'auth/custom-kerberos/login')
        expect(result[:token]).to eq(vault_token)
      end
    end
  end

  describe '.login!' do
    before do
      allow(Vault).to receive(:token=)
    end

    it 'sets the Vault token after login' do
      described_class.login!(spnego_token: spnego_token)
      expect(Vault).to have_received(:token=).with(vault_token)
    end

    it 'returns the auth result' do
      result = described_class.login!(spnego_token: spnego_token)
      expect(result[:token]).to eq(vault_token)
    end

    it 'propagates AuthError from login' do
      Legion::Settings[:crypt][:vault][:connected] = false

      expect { described_class.login!(spnego_token: spnego_token) }
        .to raise_error(Legion::Crypt::VaultKerberosAuth::AuthError, 'Vault is not connected')
    end
  end

  describe 'AuthError' do
    it 'inherits from StandardError' do
      expect(Legion::Crypt::VaultKerberosAuth::AuthError.ancestors).to include(StandardError)
    end

    it 'carries the error message' do
      err = Legion::Crypt::VaultKerberosAuth::AuthError.new('something went wrong')
      expect(err.message).to eq('something went wrong')
    end
  end

  describe 'constants' do
    it 'DEFAULT_AUTH_PATH is auth/kerberos/login' do
      expect(described_class::DEFAULT_AUTH_PATH).to eq('auth/kerberos/login')
    end
  end
end
