# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/token_renewer'

RSpec.describe Legion::Crypt::TokenRenewer do
  let(:cluster_name) { :primary }
  let(:config) do
    {
      token: 'hvs.initial-token', lease_duration: 100, renewable: true,
      connected: true, auth_method: 'kerberos', address: 'vault.example.com',
      kerberos: { service_principal: 'HTTP/vault.example.com', auth_path: 'auth/kerberos/login' }
    }
  end
  let(:vault_client) { instance_double(Vault::Client) }
  let(:auth_token) { double('AuthToken') }
  let(:renew_result) do
    double('RenewResult', auth: double('Auth', lease_duration: 200, client_token: 'hvs.renewed', renewable?: false))
  end

  let(:renewer) { described_class.new(cluster_name: cluster_name, config: config, vault_client: vault_client) }

  before do
    allow(vault_client).to receive(:auth_token).and_return(auth_token)
  end

  describe '#initialize' do
    it 'stores the cluster name' do
      expect(renewer.cluster_name).to eq(:primary)
    end

    it 'is not running after initialization' do
      expect(renewer.running?).to be false
    end
  end

  describe '#renew_token' do
    it 'calls renew_self on the vault client and updates lease_duration' do
      allow(auth_token).to receive(:renew_self).and_return(renew_result)
      result = renewer.renew_token
      expect(result).to be true
      expect(config[:lease_duration]).to eq(200)
      expect(config[:renewable]).to be(false)
    end

    it 'returns false when renewal fails' do
      allow(auth_token).to receive(:renew_self).and_raise(StandardError, 'token expired')
      result = renewer.renew_token
      expect(result).to be false
    end
  end

  describe '#reauth_kerberos' do
    it 'obtains a fresh token via KerberosAuth.login' do
      allow(Legion::Crypt::KerberosAuth).to receive(:login).and_return(
        { token: 'hvs.reauth-token', lease_duration: 300, renewable: true, policies: [], metadata: {} }
      )
      allow(vault_client).to receive(:token=)
      result = renewer.reauth_kerberos
      expect(result).to be true
      expect(config[:token]).to eq('hvs.reauth-token')
      expect(config[:lease_duration]).to eq(300)
      expect(config[:connected]).to be true
    end

    it 'returns false when re-auth fails' do
      allow(Legion::Crypt::KerberosAuth).to receive(:login)
        .and_raise(Legion::Crypt::KerberosAuth::AuthError, 'no TGT')
      result = renewer.reauth_kerberos
      expect(result).to be false
    end
  end

  describe '#sleep_duration' do
    it 'returns 75% of the lease_duration' do
      expect(renewer.sleep_duration).to eq(75)
    end

    it 'uses the ratio for short-lived tokens so renewal happens before expiry' do
      config[:lease_duration] = 10
      expect(renewer.sleep_duration).to eq(7)
    end
  end

  describe '#start and #stop' do
    it 'starts and stops the renewal thread' do
      allow(auth_token).to receive(:renew_self).and_return(renew_result)
      allow(vault_client).to receive(:token).and_return('hvs.initial-token')
      allow(auth_token).to receive(:revoke_self)
      renewer.start
      expect(renewer.running?).to be true
      renewer.stop
      expect(renewer.running?).to be false
    end
  end

  describe '#revoke_token (private)' do
    context 'when auth_method is kerberos' do
      it 'calls revoke_self on auth_token' do
        allow(vault_client).to receive(:token).and_return('hvs.initial-token')
        expect(auth_token).to receive(:revoke_self)
        renewer.send(:revoke_token)
      end
    end

    context 'when auth_method is not kerberos' do
      let(:config) do
        {
          token: 'hvs.env-token', lease_duration: 100, renewable: true,
          connected: true, auth_method: 'token', address: 'vault.example.com'
        }
      end

      it 'does not revoke the token' do
        allow(vault_client).to receive(:token).and_return('hvs.env-token')
        expect(auth_token).not_to receive(:revoke_self)
        renewer.send(:revoke_token)
      end
    end

    context 'when auth_method is nil' do
      let(:config) do
        {
          token: 'hvs.env-token', lease_duration: 100, renewable: true,
          connected: true, address: 'vault.example.com'
        }
      end

      it 'does not revoke the token' do
        allow(vault_client).to receive(:token).and_return('hvs.env-token')
        expect(auth_token).not_to receive(:revoke_self)
        renewer.send(:revoke_token)
      end
    end

    context 'when vault_client has no token' do
      it 'does not attempt revocation' do
        allow(vault_client).to receive(:token).and_return(nil)
        expect(auth_token).not_to receive(:revoke_self)
        renewer.send(:revoke_token)
      end
    end

    context 'when revoke_self raises' do
      it 'does not propagate the error' do
        allow(vault_client).to receive(:token).and_return('hvs.initial-token')
        allow(auth_token).to receive(:revoke_self).and_raise(StandardError, 'network error')
        expect { renewer.send(:revoke_token) }.not_to raise_error
      end
    end
  end

  describe '#next_backoff' do
    it 'doubles up to the cap' do
      expect(renewer.next_backoff).to eq(30)
      expect(renewer.next_backoff).to eq(60)
      expect(renewer.next_backoff).to eq(120)
      expect(renewer.next_backoff).to eq(240)
      expect(renewer.next_backoff).to eq(480)
      expect(renewer.next_backoff).to eq(600)
      expect(renewer.next_backoff).to eq(600)
    end
  end

  describe '#reset_backoff' do
    it 'resets the backoff to initial value' do
      renewer.next_backoff
      renewer.next_backoff
      renewer.reset_backoff
      expect(renewer.next_backoff).to eq(30)
    end
  end
end
