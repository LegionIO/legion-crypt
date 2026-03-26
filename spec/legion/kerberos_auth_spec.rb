# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/kerberos_auth'

RSpec.describe Legion::Crypt::KerberosAuth do
  let(:vault_client) { instance_double(Vault::Client) }
  let(:vault_logical) { double('VaultLogical') }
  let(:vault_token) { 'hvs.kerberos-token' }
  let(:auth_double) do
    double('VaultAuth',
           client_token:   vault_token,
           lease_duration: 3600,
           renewable:      true,
           policies:       %w[default legion-worker],
           metadata:       { 'username' => 'miverso2' })
  end
  let(:response_double) { double('VaultResponse', auth: auth_double) }

  before do
    stub_const('Vault::HTTPClientError', Class.new(StandardError))
    stub_const('Legion::Extensions::Kerberos::Helpers::Spnego',
               Module.new do
                 def obtain_spnego_token(service_principal:) # rubocop:disable Lint/UnusedMethodArgument
                   { success: true, token: 'fake-spnego-b64' }
                 end
               end)
    described_class.instance_variable_set(:@spnego_available, nil)
    allow(vault_client).to receive(:logical).and_return(vault_logical)
    allow(vault_logical).to receive(:write).and_return(response_double)
  end

  after do
    described_class.instance_variable_set(:@spnego_available, nil)
  end

  describe '.login' do
    it 'obtains a SPNEGO token and exchanges it for a Vault token' do
      result = described_class.login(
        vault_client:      vault_client,
        service_principal: 'HTTP/vault.example.com'
      )
      expect(result[:token]).to eq(vault_token)
      expect(result[:lease_duration]).to eq(3600)
      expect(result[:renewable]).to be true
      expect(result[:policies]).to include('legion-worker')
    end

    it 'sends the SPNEGO token to the correct auth path' do
      expect(vault_logical).to receive(:write).with(
        'auth/kerberos/login',
        authorization: 'Negotiate fake-spnego-b64'
      ).and_return(response_double)

      described_class.login(
        vault_client:      vault_client,
        service_principal: 'HTTP/vault.example.com'
      )
    end

    it 'uses a custom auth_path when provided' do
      expect(vault_logical).to receive(:write).with(
        'auth/custom/login',
        authorization: 'Negotiate fake-spnego-b64'
      ).and_return(response_double)

      described_class.login(
        vault_client:      vault_client,
        service_principal: 'HTTP/vault.example.com',
        auth_path:         'auth/custom/login'
      )
    end

    context 'when lex-kerberos is not installed' do
      before do
        hide_const('Legion::Extensions::Kerberos::Helpers::Spnego')
        described_class.instance_variable_set(:@spnego_available, nil)
      end

      it 'raises GemMissingError' do
        expect do
          described_class.login(vault_client: vault_client, service_principal: 'HTTP/vault.example.com')
        end.to raise_error(Legion::Crypt::KerberosAuth::GemMissingError, /lex-kerberos/)
      end
    end

    context 'when GSSAPI fails' do
      before do
        stub_const('Legion::Extensions::Kerberos::Helpers::Spnego',
                   Module.new do
                     def obtain_spnego_token(service_principal:) # rubocop:disable Lint/UnusedMethodArgument
                       { success: false, error: 'No credentials cache found' }
                     end
                   end)
        described_class.instance_variable_set(:@spnego_available, nil)
      end

      it 'raises AuthError with the GSSAPI message' do
        expect do
          described_class.login(vault_client: vault_client, service_principal: 'HTTP/vault.example.com')
        end.to raise_error(Legion::Crypt::KerberosAuth::AuthError, /No credentials cache found/)
      end
    end

    context 'when Vault returns no auth data' do
      before do
        allow(vault_logical).to receive(:write).and_return(double('VaultResponse', auth: nil))
      end

      it 'raises AuthError' do
        expect do
          described_class.login(vault_client: vault_client, service_principal: 'HTTP/vault.example.com')
        end.to raise_error(Legion::Crypt::KerberosAuth::AuthError, /no auth data/)
      end
    end
  end

  describe '.spnego_available?' do
    before { described_class.instance_variable_set(:@spnego_available, nil) }

    it 'returns true when lex-kerberos Spnego module is defined' do
      expect(described_class.spnego_available?).to be true
    end
  end

  describe '.reset!' do
    it 'clears the cached spnego_available state' do
      described_class.spnego_available?
      described_class.reset!
      expect(described_class.instance_variable_get(:@spnego_available)).to be_nil
    end
  end
end
