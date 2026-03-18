# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_cluster'
require 'legion/crypt/vault'

RSpec.describe Legion::Crypt::Vault do
  describe '#renew_sessions' do
    context 'when no clusters are configured (single-cluster fallback)' do
      let(:obj) do
        obj = Object.new
        obj.extend(described_class)
        obj.instance_variable_set(:@sessions, [])
        obj
      end

      it 'does not raise when sessions list is empty' do
        expect { obj.renew_sessions }.not_to raise_error
      end

      it 'calls renew_session for each session' do
        obj.instance_variable_set(:@sessions, ['lease/abc', 'lease/xyz'])
        expect(obj).to receive(:renew_session).with(session: 'lease/abc')
        expect(obj).to receive(:renew_session).with(session: 'lease/xyz')
        obj.renew_sessions
      end
    end

    context 'when clusters are configured (multi-cluster path)' do
      let(:mock_client)     { instance_double(Vault::Client) }
      let(:mock_auth_token) { double('auth_token') }
      let(:connected_cluster_config) do
        { protocol: 'https', address: 'vault.example.com', port: 8200, token: 'tok', connected: true }
      end

      let(:obj) do
        obj = Object.new
        obj.extend(Legion::Crypt::VaultCluster)
        obj.extend(described_class)
        obj.instance_variable_set(:@sessions, [])
        vault_settings_hash = { default: :primary, clusters: { primary: connected_cluster_config } }
        obj.define_singleton_method(:vault_settings) { vault_settings_hash }
        obj
      end

      before do
        allow(Vault::Client).to receive(:new).and_return(mock_client)
        allow(mock_client).to receive(:namespace=)
        allow(mock_client).to receive(:auth_token).and_return(mock_auth_token)
        allow(mock_auth_token).to receive(:renew_self)
      end

      it 'calls renew_self on the vault client for each connected cluster' do
        expect(mock_auth_token).to receive(:renew_self).once
        obj.renew_sessions
      end

      it 'captures errors per cluster without stopping' do
        allow(mock_auth_token).to receive(:renew_self).and_raise(StandardError, 'renewal failed')
        expect { obj.renew_sessions }.not_to raise_error
      end
    end
  end

  describe '#renew_cluster_tokens' do
    let(:mock_client)     { instance_double(Vault::Client) }
    let(:mock_auth_token) { double('auth_token') }
    let(:cluster_config) do
      { protocol: 'https', address: 'vault.example.com', port: 8200, token: 'tok', connected: true }
    end

    let(:obj) do
      obj = Object.new
      obj.extend(Legion::Crypt::VaultCluster)
      obj.extend(described_class)
      vault_settings_hash = { default: :primary, clusters: { primary: cluster_config } }
      obj.define_singleton_method(:vault_settings) { vault_settings_hash }
      obj
    end

    before do
      allow(Vault::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:namespace=)
      allow(mock_client).to receive(:auth_token).and_return(mock_auth_token)
      allow(mock_auth_token).to receive(:renew_self)
    end

    it 'renews tokens for each connected cluster' do
      expect(mock_auth_token).to receive(:renew_self)
      obj.renew_cluster_tokens
    end

    it 'handles errors without raising' do
      allow(mock_auth_token).to receive(:renew_self).and_raise(StandardError, 'timeout')
      expect { obj.renew_cluster_tokens }.not_to raise_error
    end
  end
end
