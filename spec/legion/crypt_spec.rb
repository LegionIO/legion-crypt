# frozen_string_literal: true

require 'spec_helper'

require 'legion/crypt'
# require 'legion/transport'
# Legion::Transport::Connection.setup

RSpec.describe Legion::Crypt do
  it 'has a version number' do
    expect(Legion::Crypt::VERSION).not_to be nil
  end

  it 'can start' do
    expect { Legion::Crypt.start }.not_to raise_exception
  end

  it 'can stop' do
    expect { Legion::Crypt.shutdown }.not_to raise_exception
  end

  describe '.verify_external_token' do
    it 'delegates to JWT.verify_with_jwks' do
      expect(Legion::Crypt::JWT).to receive(:verify_with_jwks)
        .with('token', jwks_url: 'https://example.com/keys', issuers: ['iss'], audience: 'aud')
        .and_return({ sub: 'test' })

      result = Legion::Crypt.verify_external_token(
        'token', jwks_url: 'https://example.com/keys', issuers: ['iss'], audience: 'aud'
      )
      expect(result[:sub]).to eq('test')
    end
  end

  describe '.kerberos_principal' do
    it 'delegates to KerberosAuth.kerberos_principal' do
      allow(Legion::Crypt::KerberosAuth).to receive(:kerberos_principal).and_return('miverso2@EXAMPLE.COM')
      expect(Legion::Crypt.kerberos_principal).to eq('miverso2@EXAMPLE.COM')
    end

    it 'returns nil when no Kerberos auth has occurred' do
      allow(Legion::Crypt::KerberosAuth).to receive(:kerberos_principal).and_return(nil)
      expect(Legion::Crypt.kerberos_principal).to be_nil
    end
  end

  describe 'multi-cluster module methods' do
    it 'responds to :cluster' do
      expect(Legion::Crypt).to respond_to(:cluster)
    end

    it 'responds to :clusters' do
      expect(Legion::Crypt).to respond_to(:clusters)
    end

    it 'responds to :vault_client' do
      expect(Legion::Crypt).to respond_to(:vault_client)
    end

    it 'responds to :ldap_login_all' do
      expect(Legion::Crypt).to respond_to(:ldap_login_all)
    end

    it ':clusters returns a hash' do
      expect(Legion::Crypt.clusters).to be_a(Hash)
    end
  end

  describe '.delete' do
    context 'when Vault is available' do
      let(:logical) { double('logical') }

      before do
        allow(Vault).to receive(:logical).and_return(logical)
        allow(logical).to receive(:delete).and_return(true)
      end

      it 'deletes the Vault path' do
        result = Legion::Crypt.delete('secret/data/legion/workers/w-1/entra')
        expect(logical).to have_received(:delete).with('secret/data/legion/workers/w-1/entra')
        expect(result).to include(success: true)
      end
    end

    context 'when Vault is not available' do
      before do
        allow(Vault).to receive(:logical).and_raise(StandardError, 'not connected')
      end

      it 'returns failure without raising' do
        result = Legion::Crypt.delete('secret/data/legion/workers/w-1/entra')
        expect(result[:success]).to be false
      end
    end
  end

  describe 'LeaseManager integration' do
    before do
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start_renewal_thread)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:shutdown)
    end

    it 'starts LeaseManager when vault is connected and leases are defined' do
      Legion::Settings[:crypt][:vault][:connected] = true
      Legion::Settings[:crypt][:vault][:leases] = { 'test' => { 'path' => 'secret/test' } }
      Legion::Crypt.start
      expect(Legion::Crypt::LeaseManager.instance).to have_received(:start)
    ensure
      Legion::Settings[:crypt][:vault][:connected] = false
      Legion::Settings[:crypt][:vault][:leases] = {}
    end

    it 'does not start LeaseManager when no leases are defined' do
      Legion::Settings[:crypt][:vault][:leases] = {}
      Legion::Crypt.start
      expect(Legion::Crypt::LeaseManager.instance).not_to have_received(:start)
    end

    it 'does not start LeaseManager when vault is not connected' do
      Legion::Settings[:crypt][:vault][:connected] = false
      Legion::Settings[:crypt][:vault][:leases] = { 'test' => { 'path' => 'secret/test' } }
      Legion::Crypt.start
      expect(Legion::Crypt::LeaseManager.instance).not_to have_received(:start)
    ensure
      Legion::Settings[:crypt][:vault][:leases] = {}
    end

    it 'shuts down LeaseManager during shutdown' do
      Legion::Crypt.shutdown
      expect(Legion::Crypt::LeaseManager.instance).to have_received(:shutdown)
    end

    it 'prefers the connected cluster client over the top-level vault flag' do
      leases = { 'test' => { 'path' => 'secret/test' } }
      secondary_client = instance_double(Vault::Client)
      settings_override = Legion::Settings[:crypt].merge(
        vault: Legion::Settings[:crypt][:vault].merge(leases: leases, connected: true)
      )
      allow(Legion::Crypt::LeaseManager.instance).to receive(:fetched_count).and_return(1)
      allow(Legion::Crypt).to receive(:settings).and_return(settings_override)
      allow(Legion::Crypt).to receive(:connected_clusters).and_return({ secondary: { token: 'tok-2', connected: true } })
      allow(Legion::Crypt).to receive(:selected_connected_cluster_name).and_return(:secondary)
      allow(Legion::Crypt).to receive(:vault_client).with(:secondary).and_return(secondary_client)

      Legion::Crypt.send(:start_lease_manager)

      expect(Legion::Crypt::LeaseManager.instance).to have_received(:start).with(leases, vault_client: secondary_client)
    end
  end

  describe '.start with kerberos clusters' do
    let(:mock_renewer) do
      instance_double(Legion::Crypt::TokenRenewer, start: nil, stop: nil, running?: true)
    end

    before do
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start_renewal_thread)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:shutdown)
      allow(Legion::Crypt).to receive(:connect_all_clusters)
    end

    after do
      Legion::Crypt.shutdown
      Legion::Settings[:crypt][:vault][:clusters] = {}
    end

    it 'starts a TokenRenewer for connected kerberos clusters' do
      Legion::Settings[:crypt][:vault][:clusters] = {
        primary: {
          protocol: 'https', address: 'vault.example.com', port: 8200,
          auth_method: 'kerberos', connected: true, token: 'hvs.krb-token',
          lease_duration: 3600, renewable: true,
          kerberos: { service_principal: 'HTTP/vault.example.com', auth_path: 'auth/kerberos/login' }
        }
      }
      mock_client = instance_double(Vault::Client)
      allow(Vault::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:namespace=)
      allow(Legion::Crypt::TokenRenewer).to receive(:new).and_return(mock_renewer)

      Legion::Crypt.start
      expect(Legion::Crypt::TokenRenewer).to have_received(:new)
      expect(mock_renewer).to have_received(:start)
    end

    it 'skips non-kerberos clusters' do
      Legion::Settings[:crypt][:vault][:clusters] = {
        token_based: {
          protocol: 'https', address: 'vault.example.com', port: 8200,
          token: 'hvs.static', connected: true
        }
      }
      mock_client = instance_double(Vault::Client)
      allow(Vault::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:namespace=)
      allow(mock_client).to receive(:sys).and_return(double('sys', health_status: double(initialized?: true)))

      Legion::Crypt.start
      expect(Legion::Crypt::TokenRenewer).not_to receive(:new)
    end

    it 'stops all token renewers on shutdown' do
      Legion::Settings[:crypt][:vault][:clusters] = {
        primary: {
          protocol: 'https', address: 'vault.example.com', port: 8200,
          auth_method: 'kerberos', connected: true, token: 'hvs.krb-token',
          lease_duration: 3600, renewable: true,
          kerberos: { service_principal: 'HTTP/vault.example.com', auth_path: 'auth/kerberos/login' }
        }
      }
      mock_client = instance_double(Vault::Client)
      allow(Vault::Client).to receive(:new).and_return(mock_client)
      allow(mock_client).to receive(:namespace=)
      allow(Legion::Crypt::TokenRenewer).to receive(:new).and_return(mock_renewer)

      Legion::Crypt.start
      Legion::Crypt.shutdown
      expect(mock_renewer).to have_received(:stop)
    end
  end
end
