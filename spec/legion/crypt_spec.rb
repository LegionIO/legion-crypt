# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

require 'legion/crypt'
# require 'legion/transport'
# Legion::Transport::Connection.setup

RSpec.describe Legion::Crypt do
  describe 'private key persistence' do
    let(:configuration) do
      Legion::Crypt::Settings.default.merge(save_private_key: true, vault: { token: nil, clusters: {}, leases: {}, connected: false })
    end
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    around do |example|
      Dir.mktmpdir('crypt-key') do |directory|
        Dir.chdir(directory) { example.run }
      end
    end

    before do
      described_class.shutdown
      allow(Legion::Settings).to receive(:[]).and_call_original
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
      @original_private_key = described_class.instance_variable_get(:@private_key)
      described_class.instance_variable_set(:@private_key, nil)
    end

    after do
      described_class.shutdown
      described_class.instance_variable_set(:@private_key, @original_private_key)
    end

    it 'creates owner-only key files even with a permissive umask' do
      original_umask = File.umask(0)
      described_class.start
      expect(File.stat('legionio.key').mode & 0o777).to eq(0o600)
    ensure
      File.umask(original_umask)
    end

    it 'repairs a pre-existing permissive key file before saving' do
      File.write('legionio.key', private_key.to_pem)
      File.chmod(0o644, 'legionio.key')
      described_class.start
      expect(File.stat('legionio.key').mode & 0o777).to eq(0o600)
    end

    it 'does not create a key file when saving is disabled' do
      configuration[:save_private_key] = false
      described_class.start
      expect(File.exist?('legionio.key')).to be(false)
    end
  end

  describe '.vault_connected?' do
    it 'returns true when the top-level vault flag is set' do
      allow(Legion::Crypt).to receive(:settings).and_return({ vault: { connected: true } })

      expect(Legion::Crypt.vault_connected?).to be(true)
    end

    it 'returns true when any clustered Vault client is connected' do
      allow(Legion::Crypt).to receive(:settings).and_return({ vault: { connected: false } })
      allow(Legion::Crypt).to receive(:connected_clusters).and_return({ primary: { connected: true, token: 'abc' } })

      expect(Legion::Crypt.vault_connected?).to be(true)
    end

    it 'returns false when neither the top-level flag nor clusters are connected' do
      allow(Legion::Crypt).to receive(:settings).and_return({ vault: { connected: false } })
      allow(Legion::Crypt).to receive(:connected_clusters).and_return({})

      expect(Legion::Crypt.vault_connected?).to be(false)
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
      Legion::Crypt.shutdown
      @original_vault_settings = Legion::Settings[:crypt][:vault].dup
      Legion::Settings[:crypt][:vault][:clusters] = {}
      allow(Legion::Crypt).to receive(:connect_vault)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start_renewal_thread)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:shutdown)
    end

    after do
      Legion::Crypt.shutdown
      Legion::Settings[:crypt][:vault].replace(@original_vault_settings)
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
      Legion::Crypt.start
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
      instance_double(Legion::Crypt::TokenRenewer, start: nil, request_stop: nil, stop: nil, running?: true)
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

    it 'ignores repeated start calls once the lifecycle is already running' do
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
      Legion::Crypt.start

      expect(Legion::Crypt::TokenRenewer).to have_received(:new).once
    end
  end

  describe 'failure-isolated shutdown' do
    let(:configuration) do
      Legion::Crypt::Settings.default.merge(save_private_key: false, vault: { token: nil, clusters: {}, leases: {}, connected: false })
    end

    before do
      described_class.shutdown
      Legion::Crypt::LeaseManager.instance.reset!
      allow(Legion::Settings).to receive(:[]).and_call_original
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
    end

    after { described_class.shutdown }

    it 'completes cleanup and permits restart after a session revocation fails' do
      revoked = []
      cancelled = []
      stopped = []
      sys = double('Vault sys')
      allow(Vault).to receive(:sys).and_return(sys)
      allow(sys).to receive(:revoke) do |session|
        raise 'revoke unavailable' if session == 'broken'

        revoked << session
      end
      renewer = double('legacy renewer')
      rotation = double('SVID rotation')
      allow(renewer).to receive(:cancel) { cancelled << true }
      allow(rotation).to receive(:stop) { stopped << true }

      described_class.start
      described_class.instance_variable_set(:@renewer, renewer)
      described_class.instance_variable_set(:@svid_rotation, rotation)
      described_class.add_session(path: 'broken')
      described_class.add_session(path: 'healthy')
      described_class.shutdown
      expect(revoked).to eq(['healthy'])
      expect(cancelled).to eq([true])
      expect(stopped).to eq([true])

      described_class.start
      described_class.add_session(path: 'after-restart')
      described_class.shutdown
      expect(revoked).to eq(%w[healthy after-restart])
    end

    it 'retires cached cluster clients before starting another lifecycle' do
      described_class.start
      configuration[:vault][:clusters][:primary] = {
        protocol: 'https', address: 'first.example.com', port: 8200, token: nil
      }
      previous = described_class.vault_client(:primary)
      allow(previous).to receive(:shutdown).and_call_original
      described_class.shutdown
      expect(previous).to have_received(:shutdown).once
      configuration[:vault][:clusters][:primary][:address] = 'second.example.com'
      described_class.start
      replacement = described_class.vault_client(:primary)
      expect(replacement).not_to equal(previous)
      expect(replacement.address).to eq('https://second.example.com:8200')
    end

    it 'also retires clients opened before the lifecycle starts' do
      configuration[:vault][:clusters][:primary] = {
        protocol: 'https', address: 'vault.example.com', port: 8200, token: nil
      }
      previous = described_class.vault_client(:primary)
      allow(previous).to receive(:shutdown).and_call_original
      described_class.shutdown
      expect(previous).to have_received(:shutdown).once
      described_class.start
      expect(described_class.vault_client(:primary)).not_to equal(previous)
    end
  end
end
