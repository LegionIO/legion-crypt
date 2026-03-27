# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_cluster'
require 'legion/crypt/ldap_auth'

RSpec.describe Legion::Crypt::LdapAuth do
  let(:cluster_ldap_one) do
    { protocol: 'https', address: 'vault-1.example.com', port: 8200,
      token: nil, connected: false, auth_method: 'ldap' }
  end
  let(:cluster_ldap_two) do
    { protocol: 'https', address: 'vault-2.example.com', port: 8200,
      token: nil, connected: false, auth_method: 'ldap' }
  end
  let(:cluster_token_only) do
    { protocol: 'https', address: 'vault-3.example.com', port: 8200,
      token: 'static-token', connected: true, auth_method: 'token' }
  end

  let(:test_clusters) { { one: cluster_ldap_one, two: cluster_ldap_two, three: cluster_token_only } }

  let(:test_object) do
    obj = Object.new
    obj.extend(Legion::Crypt::VaultCluster)
    obj.extend(described_class)
    vault_settings_hash = { default: :one, clusters: test_clusters }
    obj.define_singleton_method(:vault_settings) { vault_settings_hash }
    obj
  end

  let(:mock_vault_client) { instance_double(Vault::Client) }
  let(:mock_logical)      { instance_double(Vault::Logical) }
  let(:mock_secret)       { double('secret') }
  let(:mock_auth)         { double('auth') }

  before do
    allow(Vault::Client).to receive(:new).and_return(mock_vault_client)
    allow(mock_vault_client).to receive(:namespace=)
    allow(mock_vault_client).to receive(:logical).and_return(mock_logical)
    allow(mock_logical).to receive(:write).and_return(mock_secret)
    allow(mock_secret).to receive(:auth).and_return(mock_auth)
    allow(mock_auth).to receive(:client_token).and_return('new-vault-token')
    allow(mock_auth).to receive(:lease_duration).and_return(3600)
    allow(mock_auth).to receive(:renewable?).and_return(true)
    allow(mock_auth).to receive(:policies).and_return(['default'])
  end

  describe '#ldap_login' do
    it 'writes to the correct LDAP login path' do
      expect(mock_logical).to receive(:write)
        .with('auth/ldap/login/jdoe', password: 'secret')
      test_object.ldap_login(cluster_name: :one, username: 'jdoe', password: 'secret')
    end

    it 'stores the returned token in the cluster config' do
      test_object.ldap_login(cluster_name: :one, username: 'jdoe', password: 'secret')
      expect(test_clusters[:one][:token]).to eq('new-vault-token')
    end

    it 'marks the cluster as connected' do
      test_object.ldap_login(cluster_name: :one, username: 'jdoe', password: 'secret')
      expect(test_clusters[:one][:connected]).to be(true)
    end

    it 'returns a result hash with token, lease_duration, renewable, and policies' do
      result = test_object.ldap_login(cluster_name: :one, username: 'jdoe', password: 'secret')
      expect(result).to include(
        token:          'new-vault-token',
        lease_duration: 3600,
        renewable:      true,
        policies:       ['default']
      )
    end

    it 'accepts cluster_name as a string and converts to symbol' do
      result = test_object.ldap_login(cluster_name: 'one', username: 'jdoe', password: 'secret')
      expect(result[:token]).to eq('new-vault-token')
    end
  end

  describe '#ldap_login_all' do
    it 'authenticates to all clusters with auth_method=ldap' do
      results = test_object.ldap_login_all(username: 'jdoe', password: 'secret')
      expect(results.keys).to contain_exactly(:one, :two)
    end

    it 'skips clusters without auth_method=ldap' do
      results = test_object.ldap_login_all(username: 'jdoe', password: 'secret')
      expect(results).not_to have_key(:three)
    end

    it 'captures errors per cluster without stopping iteration' do
      call_count = 0
      allow(mock_logical).to receive(:write) do
        call_count += 1
        raise StandardError, 'connection refused' if call_count == 1

        mock_secret
      end

      results = test_object.ldap_login_all(username: 'jdoe', password: 'secret')
      expect(results[:one]).to include(error: 'connection refused')
      expect(results[:two]).to include(token: 'new-vault-token')
    end

    it 'returns an empty hash when no clusters use ldap auth' do
      obj = Object.new
      obj.extend(Legion::Crypt::VaultCluster)
      obj.extend(described_class)
      vault_settings_hash = { default: :three, clusters: { three: cluster_token_only } }
      obj.define_singleton_method(:vault_settings) { vault_settings_hash }

      expect(obj.ldap_login_all(username: 'jdoe', password: 'secret')).to eq({})
    end
  end
end
