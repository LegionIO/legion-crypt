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
    after { test_object.clear_vault_clients }

    it 'reuses unchanged clients while isolating different clusters' do
      alpha = test_object.vault_client(:alpha)
      expect(test_object.vault_client).to equal(alpha)
      expect(test_object.vault_client(:beta)).not_to equal(alpha)
      expect(test_object.vault_client(:unknown)).to be_nil
    end

    it 'replaces and retires clients when any connection attribute changes' do
      changes = [
        [:address, 'other.example.com', :address, 'https://other.example.com:8200'],
        [:protocol, 'http', :address, 'http://other.example.com:8200'],
        [:port, 8201, :address, 'http://other.example.com:8201'],
        [:namespace, 'tenant', :namespace, 'tenant'],
        [:tls, { verify: 'none' }, :ssl_verify, false],
        [:token, 'replacement-token', :token, 'replacement-token']
      ]
      changes.each do |key, value, attribute, expected|
        previous = test_object.vault_client(:alpha)
        allow(previous).to receive(:shutdown).and_call_original
        cluster_alpha[key] = value
        replacement = test_object.vault_client(:alpha)
        expect(replacement).not_to equal(previous)
        expect(replacement.public_send(attribute)).to eq(expected)
        expect(previous).to have_received(:shutdown).once
      end
    end

    it 'detects in-place namespace changes and inherited namespace changes' do
      configuration = { vault: { vault_namespace: +'first' } }
      allow(Legion::Settings).to receive(:[]).and_call_original
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
      first = test_object.vault_client(:alpha)
      configuration[:vault][:vault_namespace].replace('second')
      second = test_object.vault_client(:alpha)
      expect(second).not_to equal(first)
      expect(second.namespace).to eq('second')
      cluster_alpha[:namespace] = nil
      expect(test_object.vault_client(:alpha).namespace).to be_nil
    end

    it 'keeps the current client after Kerberos reauthentication updates its token' do
      cluster_alpha[:auth_method] = 'kerberos'
      cluster_alpha[:kerberos] = { service_principal: 'HTTP/vault.example.com' }
      client = test_object.vault_client(:alpha)
      allow(Legion::Crypt::KerberosAuth).to receive(:login).and_return(
        { token: 'renewed-token', lease_duration: 3600, renewable: true, metadata: {} }
      )
      renewer = Legion::Crypt::TokenRenewer.new(cluster_name: :alpha, config: cluster_alpha, vault_client: client)
      expect(renewer.reauth_kerberos).to be(true)
      expect(test_object.vault_client(:alpha)).to equal(client)
      expect(client.token).to eq('renewed-token')
    end

    it 'retires a removed cluster and does not return its obsolete client' do
      client = test_object.vault_client(:alpha)
      allow(client).to receive(:shutdown).and_call_original
      test_clusters.delete(:alpha)
      expect(test_object.vault_client(:alpha)).to be_nil
      expect(client).to have_received(:shutdown).once
    end

    it 'clears every entry even when one client cannot shut down' do
      alpha = test_object.vault_client(:alpha)
      beta = test_object.vault_client(:beta)
      allow(alpha).to receive(:shutdown).and_raise(IOError, 'failed shutdown')
      allow(beta).to receive(:shutdown).and_call_original
      test_object.clear_vault_clients
      expect(beta).to have_received(:shutdown).once
      expect(test_object.vault_client(:alpha)).not_to equal(alpha)
      expect(test_object.vault_client(:beta)).not_to equal(beta)
    end

    it 'bounds retirement without blocking a replacement client' do
      configuration = { vault: { operation_timeout: 0.03 } }
      allow(Legion::Settings).to receive(:[]).and_call_original
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
      previous = test_object.vault_client(:alpha)
      allow(previous).to receive(:shutdown) { sleep 10 }
      cluster_alpha[:address] = 'replacement.example.com'
      replacement = Timeout.timeout(0.5) { test_object.vault_client(:alpha) }
      expect(replacement.address).to eq('https://replacement.example.com:8200')
      expect(test_object.vault_client(:alpha)).to equal(replacement)
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
        allow(Legion::Settings).to receive(:[]).and_call_original
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
