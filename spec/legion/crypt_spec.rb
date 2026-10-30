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
    before { allow(described_class).to receive(:vault_settings).and_return(clusters: {}) }

    context 'when Vault is available' do
      let(:logical) { double('logical') }

      before do
        allow(described_class).to receive(:vault_client).and_return(double('core Vault client', logical: logical, namespace: nil))
        allow(logical).to receive(:delete).and_return(true)
      end

      it 'removes a previously readable Vault secret' do
        path = 'secret/data/legion/workers/w-1/entra'
        store = { path => { token: 'secret' } }
        allow(logical).to receive(:delete) { |path:| store.delete(path) }
        allow(logical).to receive(:read) do |path:|
          double('Secret', data: store[path], lease_id: nil) if store.key?(path)
        end
        expect(described_class.read(path)).to eq(token: 'secret')
        expect(described_class.delete(path)).to include(success: true)
        expect(described_class.read(path)).to be_nil
      end
    end

    context 'when Vault is not available' do
      before do
        allow(described_class).to receive(:vault_client).and_raise(StandardError, 'not connected')
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
      secondary_client = instance_double(Legion::Crypt::VaultClient)
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

  describe 'cluster token lifecycle' do
    let(:configuration) { Legion::Crypt::Settings.default.merge(save_private_key: false) }
    let(:cluster_config) do
      { protocol: 'https', address: 'vault.example.com', port: 8200, auth_method: 'ldap', connected: false }
    end
    let(:client) { described_class.vault_client(:primary) }
    let(:logical) { instance_double(Legion::Crypt::VaultClient::Logical) }
    let(:auth_token) { double('AuthToken', revoke_self: nil) }

    before do
      described_class.shutdown
      configuration[:vault].merge!(token: nil, connected: false, clusters: { primary: cluster_config }, leases: {}, operation_timeout: 0.05)
      allow(Legion::Settings).to receive(:[]).and_call_original
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
      allow(client).to receive(:logical).and_return(logical)
      allow(client).to receive(:auth_token).and_return(auth_token)
    end

    after { described_class.shutdown }

    it 'preserves automatic Kerberos reauthentication and revokes the owned token on shutdown' do
      cluster_config.merge!(auth_method: 'kerberos', kerberos: { service_principal: 'HTTP/vault.example.com' })
      attempts = 0
      renewed = Queue.new
      allow(Legion::Crypt::KerberosAuth).to receive(:login) do
        attempts += 1
        renewed << Thread.current if attempts > 1
        { token: attempts == 1 ? 'initial' : 'reauthenticated', lease_duration: attempts == 1 ? 0.08 : 60,
          renewable: false, policies: [] }
      end
      revoked = []
      allow(auth_token).to receive(:revoke_self) { revoked << client.token }
      described_class.start
      described_class.start
      worker = Timeout.timeout(1) { renewed.pop }
      Timeout.timeout(1) { sleep(0.001) until client.token == 'reauthenticated' }
      expect(described_class.vault_connected?).to be(true)
      described_class.shutdown
      expect(worker.alive?).to be(false)
      expect(revoked).to eq(['reauthenticated'])
      expect(attempts).to eq(2)
    end

    it 'replaces a pending LDAP renewal without duplicate workers and stops the replacement on shutdown' do
      entered = Queue.new
      blocked = Queue.new
      first = double('Secret', auth: double('Auth', client_token: 'first', lease_duration: 0.08, renewable?: true, policies: []))
      second = double('Secret', auth: double('Auth', client_token: 'second', lease_duration: 60, renewable?: false, policies: []))
      allow(logical).to receive(:write).and_return(first, second)
      allow(auth_token).to receive(:renew_self) do
        entered << Thread.current
        blocked.pop
      end
      expect(Legion::Crypt::KerberosAuth).not_to receive(:login)
      described_class.start
      described_class.ldap_login(cluster_name: :primary, username: 'user', password: 'one-use')
      previous = Timeout.timeout(1) { entered.pop }
      described_class.ldap_login(cluster_name: :primary, username: 'user', password: 'one-use')
      workers = Thread.list.select { |thread| thread.name == 'vault-renewer-primary' }
      expect(previous.alive?).to be(false)
      expect(workers.size).to eq(1)
      expect(client.token).to eq('second')
      expect(described_class.vault_connected?).to be(true)
      described_class.shutdown
      expect(workers.first.alive?).to be(false)
    end

    it 'does not install an LDAP login response completing after shutdown' do
      operation = nil
      release = nil
      entered = Queue.new
      release = Queue.new
      allow(logical).to receive(:write) do
        entered << true
        release.pop
        double('Secret', auth: double('Auth', client_token: 'late', lease_duration: 60, renewable?: true, policies: []))
      end
      described_class.start
      operation = Thread.new do
        described_class.ldap_login(cluster_name: :primary, username: 'user', password: 'one-use')
      rescue StandardError => e
        e
      end
      Timeout.timeout(1) { entered.pop }
      described_class.shutdown
      release << true
      expect(operation.join(1)).to eq(operation)
      expect(operation.value).to be_a(RuntimeError)
      expect(cluster_config[:token]).to be_nil
      expect(described_class.connected_clusters).to be_empty
      expect(Thread.list.none? { |thread| thread.name == 'vault-renewer-primary' }).to be(true)
    ensure
      release << true if release && operation&.alive?
      operation&.join(1)
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
      allow(described_class).to receive(:vault_client).and_return(double('core Vault client', sys: sys))
      allow(sys).to receive(:revoke) do |lease_id:|
        raise 'revoke unavailable' if lease_id == 'broken'

        revoked << lease_id
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
