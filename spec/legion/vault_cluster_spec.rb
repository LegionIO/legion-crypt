# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_cluster'
require 'legion/crypt/kerberos_auth'

RSpec.describe Legion::Crypt::VaultCluster do
  let(:cluster_alpha) do
    { protocol: 'https', address: 'vault-alpha.example.com', port: 8200, token: 'token-alpha', connected: true }
  end
  let(:cluster_beta) do
    { protocol: 'https', address: 'vault-beta.example.com', port: 8200, token: 'token-beta', connected: false }
  end
  let(:cluster_gamma) do
    { protocol: 'http', address: 'vault-gamma.example.com', port: 8200, token: nil, connected: false }
  end

  let(:test_clusters) { { alpha: cluster_alpha, beta: cluster_beta, gamma: cluster_gamma } }

  let(:test_object) do
    obj = Object.new
    obj.extend(described_class)
    vault_settings_hash = { default: :alpha, clusters: test_clusters }
    obj.define_singleton_method(:vault_settings) { vault_settings_hash }
    obj
  end

  describe '#default_cluster_name' do
    it 'returns the configured default cluster name as a symbol' do
      expect(test_object.default_cluster_name).to eq(:alpha)
    end

    context 'when default is nil' do
      let(:test_object) do
        obj = Object.new
        obj.extend(described_class)
        vault_settings_hash = { default: nil, clusters: test_clusters }
        obj.define_singleton_method(:vault_settings) { vault_settings_hash }
        obj
      end

      it 'returns the first cluster key' do
        expect(test_object.default_cluster_name).to eq(:alpha)
      end
    end
  end

  describe '#clusters' do
    it 'returns all clusters' do
      expect(test_object.clusters).to eq(test_clusters)
    end

    context 'when clusters key is missing from vault_settings' do
      let(:test_object) do
        obj = Object.new
        obj.extend(described_class)
        obj.define_singleton_method(:vault_settings) { { default: nil } }
        obj
      end

      it 'returns an empty hash' do
        expect(test_object.clusters).to eq({})
      end
    end
  end

  describe '#cluster' do
    it 'returns the default cluster config when no name is given' do
      expect(test_object.cluster).to eq(cluster_alpha)
    end

    it 'returns the named cluster config' do
      expect(test_object.cluster(:beta)).to eq(cluster_beta)
    end

    it 'returns nil for an unknown cluster name' do
      expect(test_object.cluster(:unknown)).to be_nil
    end
  end

  describe '#connected_clusters' do
    it 'returns only clusters with a token AND connected=true' do
      result = test_object.connected_clusters
      expect(result.keys).to eq([:alpha])
    end

    it 'excludes clusters without a token' do
      expect(test_object.connected_clusters).not_to have_key(:gamma)
    end

    it 'excludes clusters that have a token but are not connected' do
      expect(test_object.connected_clusters).not_to have_key(:beta)
    end
  end

  describe '#vault_client' do
    let(:mock_client) { instance_double(Vault::Client) }

    before do
      allow(Vault::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:namespace=)
    end

    it 'returns a Vault::Client for the default cluster' do
      expect(Vault::Client).to receive(:new).with(
        address:    'https://vault-alpha.example.com:8200',
        token:      'token-alpha',
        ssl_verify: true
      ).and_return(mock_client)
      expect(test_object.vault_client).to eq(mock_client)
    end

    it 'returns a Vault::Client for a named cluster' do
      expect(Vault::Client).to receive(:new).with(
        address:    'https://vault-beta.example.com:8200',
        token:      'token-beta',
        ssl_verify: true
      ).and_return(mock_client)
      expect(test_object.vault_client(:beta)).to eq(mock_client)
    end

    it 'memoizes the client per cluster name' do
      expect(Vault::Client).to receive(:new).once.and_return(mock_client)
      test_object.vault_client(:alpha)
      test_object.vault_client(:alpha)
    end

    it 'creates separate clients for different cluster names' do
      mock_beta = instance_double(Vault::Client)
      allow(mock_beta).to receive(:namespace=)
      allow(Vault::Client).to receive(:new).and_return(mock_client, mock_beta)

      client_alpha = test_object.vault_client(:alpha)
      client_beta  = test_object.vault_client(:beta)
      expect(client_alpha).not_to eq(client_beta)
    end

    it 'returns nil when the cluster config is not a hash' do
      expect(test_object.vault_client(:unknown)).to be_nil
    end

    context 'when cluster config includes a namespace' do
      let(:test_clusters_with_ns) do
        { alpha: cluster_alpha.merge(namespace: 'admin') }
      end

      let(:test_object) do
        obj = Object.new
        obj.extend(described_class)
        vault_settings_hash = { default: :alpha, clusters: test_clusters_with_ns }
        obj.define_singleton_method(:vault_settings) { vault_settings_hash }
        obj
      end

      it 'sets the namespace on the client' do
        expect(mock_client).to receive(:namespace=).with('admin')
        test_object.vault_client(:alpha)
      end
    end

    context 'when cluster config has no namespace but Settings has vault_namespace' do
      let(:test_object) do
        obj = Object.new
        obj.extend(described_class)
        vault_settings_hash = { default: :alpha, clusters: { alpha: cluster_alpha } }
        obj.define_singleton_method(:vault_settings) { vault_settings_hash }
        obj
      end

      before do
        stub_const('Legion::Settings', Module.new do
          def self.[](key)
            { vault: { vault_namespace: 'legionio' } } if key == :crypt
          end
        end)
      end

      it 'falls back to vault_namespace from Settings' do
        expect(mock_client).to receive(:namespace=).with('legionio')
        test_object.vault_client(:alpha)
      end
    end
  end

  describe '#connect_all_clusters' do
    let(:mock_alpha_client) { instance_double(Vault::Client) }
    let(:mock_sys) { instance_double(Vault::Sys) }
    let(:mock_health) { double('health', initialized?: true) }

    before do
      allow(Vault::Client).to receive(:new).and_return(mock_alpha_client)
      allow(mock_alpha_client).to receive(:namespace=)
      allow(mock_alpha_client).to receive(:sys).and_return(mock_sys)
      allow(mock_sys).to receive(:health_status).and_return(mock_health)
    end

    it 'skips clusters without a token' do
      results = test_object.connect_all_clusters
      expect(results).not_to have_key(:gamma)
    end

    it 'sets connected=true for successfully connected clusters' do
      results = test_object.connect_all_clusters
      expect(results[:alpha]).to be(true)
    end

    it 'sets connected=false on error' do
      allow(mock_alpha_client).to receive(:sys).and_raise(StandardError, 'connection refused')
      results = test_object.connect_all_clusters
      expect(results[:alpha]).to be(false)
    end

    context 'with auth_method: kerberos' do
      let(:krb_cluster) do
        {
          protocol: 'https', address: 'vault.example.com', port: 8200,
          auth_method: 'kerberos', connected: false,
          kerberos: { service_principal: 'HTTP/vault.example.com', auth_path: 'auth/kerberos/login' }
        }
      end

      let(:test_clusters) { { krb: krb_cluster } }

      it 'authenticates via KerberosAuth and sets the token' do
        allow(Legion::Crypt::KerberosAuth).to receive(:login).and_return(
          { token: 'hvs.krb-token', lease_duration: 3600, renewable: true, policies: [], metadata: {} }
        )
        allow(Vault::Client).to receive(:new).and_return(mock_alpha_client)
        allow(mock_alpha_client).to receive(:namespace=)
        allow(mock_alpha_client).to receive(:token=)

        results = test_object.connect_all_clusters
        expect(results[:krb]).to be true
        expect(krb_cluster[:token]).to eq('hvs.krb-token')
        expect(krb_cluster[:connected]).to be true
      end

      it 'sets the token on the cached vault_client after kerberos auth' do
        allow(Legion::Crypt::KerberosAuth).to receive(:login).and_return(
          { token: 'hvs.krb-token', lease_duration: 3600, renewable: true, policies: [], metadata: {} }
        )
        allow(Vault::Client).to receive(:new).and_return(mock_alpha_client)
        allow(mock_alpha_client).to receive(:namespace=)
        expect(mock_alpha_client).to receive(:token=).with('hvs.krb-token')

        test_object.connect_all_clusters
      end

      it 'handles KerberosAuth failure gracefully' do
        allow(Legion::Crypt::KerberosAuth).to receive(:login)
          .and_raise(Legion::Crypt::KerberosAuth::AuthError, 'no TGT')
        allow(Vault::Client).to receive(:new).and_return(mock_alpha_client)
        allow(mock_alpha_client).to receive(:namespace=)

        results = test_object.connect_all_clusters
        expect(results[:krb]).to be false
        expect(krb_cluster[:connected]).to be false
      end

      it 'handles missing lex-kerberos gem gracefully' do
        allow(Legion::Crypt::KerberosAuth).to receive(:login)
          .and_raise(Legion::Crypt::KerberosAuth::GemMissingError, 'lex-kerberos required')
        allow(Vault::Client).to receive(:new).and_return(mock_alpha_client)
        allow(mock_alpha_client).to receive(:namespace=)

        results = test_object.connect_all_clusters
        expect(results[:krb]).to be false
      end

      context 'without service_principal configured' do
        let(:krb_cluster) do
          {
            protocol: 'https', address: 'vault.example.com', port: 8200,
            auth_method: 'kerberos', connected: false,
            kerberos: { service_principal: nil, auth_path: 'auth/kerberos/login' }
          }
        end

        it 'skips the cluster' do
          results = test_object.connect_all_clusters
          expect(results[:krb]).to be false
        end
      end
    end

    context 'with auth_method: ldap' do
      let(:ldap_cluster) do
        { protocol: 'https', address: 'vault.example.com', port: 8200,
          auth_method: 'ldap', connected: false }
      end

      let(:test_clusters) { { ldap: ldap_cluster } }

      it 'skips ldap clusters' do
        results = test_object.connect_all_clusters
        expect(results).not_to have_key(:ldap)
      end
    end

    context 'when a token-based cluster connects successfully' do
      it 'sets Legion::Settings[:crypt][:vault][:connected] in multi-cluster mode' do
        vault_hash = { connected: false }
        crypt_hash = { vault: vault_hash }
        stub_const('Legion::Settings', Module.new do
          define_singleton_method(:[]) { |_k| crypt_hash }
        end)
        allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(crypt_hash)

        test_object.connect_all_clusters
        expect(vault_hash[:connected]).to be(true)
      end
    end
  end

  describe '#sync_vault_connected (via connect_all_clusters)' do
    it 'updates the top-level vault connected flag in multi-cluster mode' do
      vault_hash = { connected: false }
      crypt_hash = { vault: vault_hash }

      mock_client  = instance_double(Vault::Client)
      mock_sys     = instance_double(Vault::Sys)
      mock_health  = double('health', initialized?: true)

      allow(Vault::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:namespace=)
      allow(mock_client).to receive(:sys).and_return(mock_sys)
      allow(mock_sys).to receive(:health_status).and_return(mock_health)
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(crypt_hash)

      test_object.connect_all_clusters
      expect(vault_hash[:connected]).to be(true)
    end

    it 'does not raise when Legion::Settings is not defined' do
      hide_const('Legion::Settings')
      expect { test_object.connect_all_clusters }.not_to raise_error
    end
  end
end
