# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

require 'legion/crypt'
# require 'legion/transport'
# Legion::Transport::Connection.setup

RSpec.describe Legion::Crypt do
  describe 'private key persistence' do
    let(:configuration) do
      Legion::Crypt::Settings.default.merge(save_private_key: true, vault: Legion::Crypt::Settings.vault.merge(token: nil))
    end
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    around do |example|
      Dir.mktmpdir('crypt-key') do |directory|
        Dir.chdir(directory) { example.run }
      end
    end

    before do
      described_class.shutdown
      Legion::Settings.set_prop(:crypt, configuration)
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
    let(:configuration) { Legion::Crypt::Settings.default }

    before { Legion::Settings.set_prop(:crypt, configuration) }

    it 'returns true when the top-level vault flag is set' do
      configuration[:vault][:connected] = true

      expect(Legion::Crypt.vault_connected?).to be(true)
    end

    it 'returns true when any clustered Vault client is connected' do
      configuration[:vault][:connected] = false
      configuration[:vault][:clusters][:primary] = { connected: true, token: 'abc' }

      expect(Legion::Crypt.vault_connected?).to be(true)
    end

    it 'returns false when neither the top-level flag nor clusters are connected' do
      configuration[:vault][:connected] = false

      expect(Legion::Crypt.vault_connected?).to be(false)
    end

    it 'propagates invalid settings structure instead of reporting a disconnected Vault' do
      configuration[:vault][:clusters] = nil

      expect { described_class.vault_connected? }.to raise_error(NoMethodError)
    end
  end

  describe '.delete' do
    before { Legion::Settings.set_prop(:crypt, Legion::Crypt::Settings.default) }

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

  describe 'startup failure handling' do
    before do
      described_class.shutdown
      Legion::Settings[:crypt][:save_private_key] = false
      Legion::Settings[:crypt][:vault][:token] = nil
    end

    after { described_class.shutdown }

    it 'propagates invalid lease configuration instead of completing startup' do
      Legion::Settings[:crypt][:vault][:leases] = nil

      expect { described_class.start(mode: :infra) }.to raise_error(NoMethodError)
    end

    it 'propagates SPIFFE startup programming errors instead of completing startup' do
      Legion::Settings.set_prop(:security, { spiffe: { enabled: true } })
      failure = ArgumentError.new('invalid rotation constructor arguments')
      allow(Legion::Crypt::Spiffe::SvidRotation).to receive(:new).and_raise(failure)

      expect { described_class.start }.to(raise_error { |error| expect(error).to equal(failure) })
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
      secondary_client = instance_double(Legion::Crypt::Vault::Client)
      Legion::Settings[:crypt][:vault].merge!(leases: leases, connected: true)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:fetched_count).and_return(1)
      allow(Legion::Crypt).to receive(:connected_clusters).and_return({ secondary: { token: 'tok-2', connected: true } })
      allow(Legion::Crypt).to receive(:selected_connected_cluster_name).and_return(:secondary)
      allow(Legion::Crypt).to receive(:vault_client).with(:secondary).and_return(secondary_client)

      Legion::Crypt.send(:start_lease_manager)

      expect(Legion::Crypt::LeaseManager.instance).to have_received(:start).with(leases, vault_client: secondary_client)
    end

    it 'uses the infra PostgreSQL lease without mutating configured runtime leases' do
      leases = {
        postgresql: { path: 'postgresql/creds/node' },
        redis:      { path: 'redis/creds/agent' }
      }
      client = instance_double(Legion::Crypt::Vault::Client)
      Legion::Settings[:crypt][:vault].merge!(leases: leases, connected: true)
      allow(Legion::Crypt).to receive(:connected_clusters).and_return({})
      allow(Legion::Crypt).to receive(:vault_client).and_return(client)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:fetched_count).and_return(2)

      Legion::Crypt.send(:start_lease_manager, mode: :infra)

      expect(Legion::Crypt::LeaseManager.instance).to have_received(:start).with(
        {
          postgresql: { path: 'postgresql/creds/infra' },
          redis:      { path: 'redis/creds/agent' }
        },
        vault_client: client
      )
      expect(leases[:postgresql][:path]).to eq('postgresql/creds/node')
    end
  end

  describe 'cluster token lifecycle' do
    let(:configuration) { Legion::Crypt::Settings.default.merge(save_private_key: false) }
    let(:cluster_config) do
      { protocol: 'https', address: 'vault.example.com', port: 8200, auth_method: 'ldap', connected: false }
    end
    let(:client) { described_class.vault_client(:primary) }
    let(:logical) { instance_double(Legion::Crypt::Vault::Client::Logical) }
    let(:auth_token) { double('AuthToken', revoke_self: nil) }

    before do
      described_class.shutdown
      configuration[:vault].merge!(token: nil, connected: false, clusters: { primary: cluster_config }, leases: {}, operation_timeout: 0.05)
      Legion::Settings.set_prop(:crypt, configuration)
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

    it 'rejects a login through a displaced client without stopping other token workers' do
      Legion::Settings[:crypt][:vault][:clusters] = {}
      root = described_class.vault_client
      root_auth = double('RootAuthToken', revoke_self: nil)
      allow(root).to receive(:auth_token).and_return(root_auth)
      described_class.install_vault_grant(client: root, config: Legion::Settings[:crypt][:vault], auth_method: 'kerberos',
                                          grant: { token: 'root-token', lease_duration: 60, renewable: false },
                                          generation: described_class.vault_auth_generation)
      Legion::Settings[:crypt][:vault][:clusters] = { primary: cluster_config }
      logins = 0
      allow(logical).to receive(:write) do
        logins += 1
        if logins == 2
          cluster_config[:namespace] = 'replacement'
          described_class.vault_client(:primary)
        end
        double('Secret', auth: double('Auth', client_token: "ldap-#{logins}", lease_duration: 60, renewable?: true, policies: []))
      end
      described_class.ldap_login(cluster_name: :primary, username: 'user', password: 'one-use')
      workers = Thread.list.select { |thread| thread.name&.start_with?('vault-renewer-') }

      expect { described_class.ldap_login(cluster_name: :primary, username: 'user', password: 'one-use') }
        .to raise_error(IOError, /replaced during authentication/)
      expect(workers.map(&:name)).to include('vault-renewer-', 'vault-renewer-primary')
      expect(workers).to all(be_alive)
      expect(root_auth).not_to have_received(:revoke_self)
      expect(cluster_config[:token]).to eq('ldap-1')
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
      Legion::Crypt::Settings.default.merge(save_private_key: false, vault: Legion::Crypt::Settings.vault.merge(token: nil))
    end

    before do
      described_class.shutdown
      Legion::Crypt::LeaseManager.instance.reset!
      Legion::Settings.set_prop(:crypt, configuration)
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

RSpec.describe 'Legion::Crypt JWT convenience methods' do
  around do |example|
    original = Legion::Settings[:crypt]
    Legion::Settings.set_prop(:crypt, Legion::Crypt::Settings.default.merge(cluster_secret: SecureRandom.hex(32)))
    example.run
  ensure
    Legion::Settings.set_prop(:crypt, original)
  end

  describe '.issue_token' do
    it 'issues an HS256 token using cluster secret' do
      token = Legion::Crypt.issue_token({ node_id: 'test' })
      expect(token).to be_a(String)
      expect(token.split('.').length).to eq(3)
    end

    it 'issues an RS256 token using private key' do
      token = Legion::Crypt.issue_token({ node_id: 'test' }, algorithm: 'RS256')
      expect(token).to be_a(String)

      decoded = Legion::Crypt::JWT.decode(token)
      expect(decoded[:node_id]).to eq('test')
    end

    it 'uses default ttl from settings' do
      token = Legion::Crypt.issue_token({ node_id: 'test' })
      decoded = Legion::Crypt::JWT.decode(token)
      expect(decoded[:exp] - decoded[:iat]).to eq(3600)
    end

    it 'allows overriding ttl' do
      token = Legion::Crypt.issue_token({ node_id: 'test' }, ttl: 120)
      decoded = Legion::Crypt::JWT.decode(token)
      expect(decoded[:exp] - decoded[:iat]).to eq(120)
    end
  end

  describe '.verify_token' do
    it 'verifies an HS256 token' do
      token = Legion::Crypt.issue_token({ node_id: 'verify-test' })
      result = Legion::Crypt.verify_token(token)
      expect(result[:node_id]).to eq('verify-test')
    end

    it 'verifies an RS256 token' do
      token = Legion::Crypt.issue_token({ node_id: 'rs256-test' }, algorithm: 'RS256')
      result = Legion::Crypt.verify_token(token, algorithm: 'RS256')
      expect(result[:node_id]).to eq('rs256-test')
    end

    it 'raises for expired tokens' do
      token = Legion::Crypt.issue_token({ node_id: 'expired' }, ttl: -1)
      expect do
        Legion::Crypt.verify_token(token)
      end.to raise_error(Legion::Crypt::JWT::ExpiredTokenError)
    end

    it 'round-trips correctly' do
      payload = { node_id: 'round-trip', extensions: %w[lex-redis lex-http] }
      token = Legion::Crypt.issue_token(payload)
      result = Legion::Crypt.verify_token(token)
      expect(result[:node_id]).to eq('round-trip')
      expect(result[:extensions]).to eq(%w[lex-redis lex-http])
    end

    it 'honors disabled verification after replacing live JWT configuration' do
      token = Legion::Crypt.issue_token({ node_id: 'expired' }, ttl: -1)
      replacement = Legion::Settings[:crypt].merge(
        jwt: Legion::Settings[:crypt][:jwt].merge(verify_expiration: false, verify_issuer: false, issuer: 'other')
      )
      Legion::Settings.set_prop(:crypt, replacement)
      expect(Legion::Crypt.verify_token(token)[:node_id]).to eq('expired')

      Legion::Settings[:crypt][:jwt][:verify_expiration] = true
      expect { Legion::Crypt.verify_token(token) }.to raise_error(Legion::Crypt::JWT::ExpiredTokenError)
    end
  end
end

RSpec.describe Legion::Crypt do
  let(:vault_response) do
    double('Vault::Secret',
           data:           { username: 'bootstrap_user', password: 'bootstrap_pass' },
           lease_id:       'rabbitmq/creds/legionio-bootstrap/abc123',
           lease_duration: 300,
           renewable?:     false)
  end

  let(:vault_response_string_keys) do
    double('Vault::Secret',
           data:           { 'username' => 'bootstrap_user_str', 'password' => 'bootstrap_pass_str' },
           lease_id:       'rabbitmq/creds/legionio-bootstrap/str123',
           lease_duration: 300,
           renewable?:     false)
  end

  let(:identity_response) do
    double('Vault::Secret',
           data:           { username: 'identity_user', password: 'identity_pass' },
           lease_id:       'rabbitmq/creds/legionio-infra/def456',
           lease_duration: 604_800,
           renewable?:     true)
  end

  let(:identity_response_string_keys) do
    double('Vault::Secret',
           data:           { 'username' => 'identity_user_str', 'password' => 'identity_pass_str' },
           lease_id:       'rabbitmq/creds/legionio-infra/str456',
           lease_duration: 604_800,
           renewable?:     true)
  end

  let(:logical_double) { double('Vault::Logical') }
  let(:sys_double)     { instance_double(Legion::Crypt::Vault::Client::Sys) }
  let(:vault_client) { double('Vault::Client', logical: logical_double, sys: sys_double) }
  let(:manager) { Legion::Crypt::LeaseManager.instance }

  before do
    allow(Legion::Crypt).to receive(:vault_client).and_return(vault_client)
    allow(logical_double).to receive(:read).and_return(vault_response)
    allow(sys_double).to receive(:revoke).and_return(true)
    @transport_settings = Legion::Settings.loader.settings[:transport]
    Legion::Settings.loader.settings[:transport] = { connection: { vhost: '/' } }
    described_class.instance_variable_set(:@bootstrap_lease_id, nil)
    described_class.instance_variable_set(:@bootstrap_lease_expires, nil)
    manager.reset!
    manager.start({}, vault_client: vault_client)
  end

  after do
    manager.reset!
    Legion::Settings.loader.settings[:transport] = @transport_settings
  end

  describe '.dynamic_rmq_creds?' do
    it 'returns true when the setting is true' do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = true
      expect(described_class.dynamic_rmq_creds?).to be(true)
    ensure
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
    end

    it 'returns false when the setting is false' do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
      expect(described_class.dynamic_rmq_creds?).to be(false)
    end

    it 'returns false when the setting is absent' do
      Legion::Settings[:crypt][:vault].delete(:dynamic_rmq_creds)
      expect(described_class.dynamic_rmq_creds?).to be(false)
    ensure
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
    end
  end

  describe '.fetch_bootstrap_rmq_creds' do
    before do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = true
      Legion::Settings[:crypt][:vault][:connected] = true
      Legion::Settings.loader.settings[:transport] ||= {}
      Legion::Settings.loader.settings[:transport][:connection] ||= {}
    end

    after do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
    end

    it 'writes username to the transport connection settings' do
      described_class.fetch_bootstrap_rmq_creds
      conn = Legion::Settings.loader.settings.dig(:transport, :connection)
      expect(conn[:user]).to eq('bootstrap_user')
    end

    it 'writes password to the transport connection settings' do
      described_class.fetch_bootstrap_rmq_creds
      conn = Legion::Settings.loader.settings.dig(:transport, :connection)
      expect(conn[:password]).to eq('bootstrap_pass')
    end

    it 'propagates programming errors without installing bootstrap credentials' do
      failure = NoMethodError.new('invalid credential acquisition call')
      connection = Legion::Settings[:transport][:connection].dup
      allow(logical_double).to receive(:read).and_raise(failure)

      expect { described_class.fetch_bootstrap_rmq_creds }.to(raise_error { |error| expect(error).to equal(failure) })
      expect(Legion::Settings[:transport][:connection]).to eq(connection)
      expect(described_class.instance_variable_get(:@bootstrap_lease_id)).to be_nil
    end

    it 'preserves credentials after an operational failure and permits a later acquisition' do
      connection = Legion::Settings[:transport][:connection].dup
      allow(logical_double).to receive(:read).and_raise(IOError, 'Vault unavailable')

      described_class.fetch_bootstrap_rmq_creds

      expect(Legion::Settings[:transport][:connection]).to eq(connection)
      expect(described_class.instance_variable_get(:@bootstrap_lease_id)).to be_nil
      allow(logical_double).to receive(:read).and_return(vault_response)
      described_class.fetch_bootstrap_rmq_creds
      expect(Legion::Settings[:transport][:connection]).to include(user: 'bootstrap_user', password: 'bootstrap_pass')
    end

    context 'when Vault returns string-keyed data' do
      before { allow(logical_double).to receive(:read).and_return(vault_response_string_keys) }

      it 'writes username to transport connection settings from string key' do
        described_class.fetch_bootstrap_rmq_creds
        conn = Legion::Settings.loader.settings.dig(:transport, :connection)
        expect(conn[:user]).to eq('bootstrap_user_str')
      end

      it 'writes password to transport connection settings from string key' do
        described_class.fetch_bootstrap_rmq_creds
        conn = Legion::Settings.loader.settings.dig(:transport, :connection)
        expect(conn[:password]).to eq('bootstrap_pass_str')
      end
    end

    context 'when vault is not connected' do
      before { Legion::Settings[:crypt][:vault][:connected] = false }

      it 'returns nil without reading from Vault' do
        expect(logical_double).not_to receive(:read)
        expect(described_class.fetch_bootstrap_rmq_creds).to be_nil
      end
    end

    context 'when dynamic_rmq_creds? is false' do
      before { Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false }

      it 'returns nil without reading from Vault' do
        expect(logical_double).not_to receive(:read)
        expect(described_class.fetch_bootstrap_rmq_creds).to be_nil
      end
    end
  end

  describe '.swap_to_identity_creds' do
    let(:transport_connection_double) do
      double('Legion::Transport::Connection', force_reconnect: true, session_open?: true)
    end
    let(:connection_settings) { Legion::Settings.loader.settings[:transport][:connection] }
    let(:bootstrap_lease_id) { 'boot/lease/xyz789' }

    before do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = true
      allow(described_class).to receive(:vault_connected?).and_return(true)
      allow(logical_double).to receive(:read).with(path: 'rabbitmq/creds/legionio-infra').and_return(identity_response)
      allow(logical_double).to receive(:read).with(path: 'rabbitmq/creds/legionio-worker').and_return(identity_response)
      allow(logical_double).to receive(:read).with(path: 'rabbitmq/creds/legionio-custom').and_return(identity_response)
      stub_const('Legion::Transport::Connection', transport_connection_double)
      connection_settings.merge!(user: 'bootstrap_user', password: 'bootstrap_pass')
      described_class.instance_variable_set(:@bootstrap_lease_id, bootstrap_lease_id)
    end

    after do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
    end

    it 'does not acquire credentials when Vault is disconnected' do
      allow(described_class).to receive(:vault_connected?).and_return(false)
      expect(logical_double).not_to receive(:read)
      described_class.swap_to_identity_creds(mode: :agent)
    end

    it 'does not acquire credentials when dynamic credentials are disabled' do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
      expect(logical_double).not_to receive(:read)
      described_class.swap_to_identity_creds(mode: :agent)
    end

    it 'does not acquire credentials in lite mode' do
      expect(logical_double).not_to receive(:read)
      described_class.swap_to_identity_creds(mode: :lite)
    end

    { agent: 'legionio-infra', infra: 'legionio-infra', worker: 'legionio-worker', custom: 'legionio-custom' }.each do |mode, role|
      it "acquires the #{role} role for #{mode} mode" do
        expect(logical_double).to receive(:read).with(path: "rabbitmq/creds/#{role}").and_return(identity_response)
        described_class.swap_to_identity_creds(mode: mode)
        expect(manager.fetch(:rabbitmq, :username)).to eq('identity_user')
      end
    end

    it 'publishes credentials and revokes bootstrap only after the new session is confirmed open' do
      events = []
      allow(transport_connection_double).to receive(:force_reconnect) do
        expect(connection_settings).to include(user: 'identity_user', password: 'identity_pass', vhost: '/')
        events << :reconnect
        true
      end
      allow(transport_connection_double).to receive(:session_open?) do
        events << :open
        true
      end
      allow(sys_double).to receive(:revoke).with(lease_id: bootstrap_lease_id) { events << :revoke_bootstrap }

      described_class.swap_to_identity_creds(mode: :agent)

      expect(events).to eq(%i[reconnect open revoke_bootstrap])
      expect(manager.fetch(:rabbitmq, :password)).to eq('identity_pass')
      expect(manager.active_leases[:rabbitmq][:lease_id]).to eq(identity_response.lease_id)
    end

    it 'creates missing credential destinations without removing existing connection options' do
      connection_settings.delete(:user)
      connection_settings.delete(:password)

      described_class.swap_to_identity_creds(mode: :agent)

      expect(connection_settings).to include(user: 'identity_user', password: 'identity_pass', vhost: '/')
    end

    it 'creates the transport connection settings when absent' do
      Legion::Settings.loader.settings.delete(:transport)

      described_class.swap_to_identity_creds(mode: :agent)

      expect(Legion::Settings.loader.settings.dig(:transport, :connection)).to include(user: 'identity_user', password: 'identity_pass')
    end

    it 'installs string-keyed credentials through the same transaction' do
      allow(logical_double).to receive(:read).with(path: 'rabbitmq/creds/legionio-infra').and_return(identity_response_string_keys)

      described_class.swap_to_identity_creds(mode: :agent)

      expect(connection_settings).to include(user: 'identity_user_str', password: 'identity_pass_str')
      expect(manager.fetch('rabbitmq', 'username')).to eq('identity_user_str')
      expect(sys_double).to have_received(:revoke).with(lease_id: bootstrap_lease_id)
    end

    it 'retains bootstrap and existing settings when acquisition returns no response' do
      allow(logical_double).to receive(:read).with(path: 'rabbitmq/creds/legionio-infra').and_return(nil)

      expect { described_class.swap_to_identity_creds(mode: :agent) }.to raise_error(RuntimeError)

      expect(connection_settings).to include(user: 'bootstrap_user', password: 'bootstrap_pass')
      expect(sys_double).not_to have_received(:revoke).with(lease_id: bootstrap_lease_id)
      described_class.revoke_bootstrap_lease
      expect(sys_double).to have_received(:revoke).with(lease_id: bootstrap_lease_id)
    end

    it 'installs credentials without requiring a reconnect when the transport consumer is absent' do
      hide_const('Legion::Transport::Connection')

      described_class.swap_to_identity_creds(mode: :agent)

      expect(connection_settings).to include(user: 'identity_user', password: 'identity_pass')
      expect(manager.fetch(:rabbitmq, :username)).to eq('identity_user')
      expect(sys_double).to have_received(:revoke).with(lease_id: bootstrap_lease_id)
    end

    context 'with an existing manager lease' do
      before do
        manager.start({ 'rabbitmq' => { path: 'rabbitmq/creds/previous' } }, vault_client: vault_client)
      end

      shared_examples 'a rejected identity handoff' do
        it 'raises while preserving bootstrap, prior settings, and the prior managed lease' do
          expect { described_class.swap_to_identity_creds(mode: :agent) }.to raise_error(RuntimeError)

          expect(connection_settings).to include(user: 'bootstrap_user', password: 'bootstrap_pass', vhost: '/')
          expect(manager.fetch(:rabbitmq, :username)).to eq('bootstrap_user')
          expect(manager.fetch(:rabbitmq, :password)).to eq('bootstrap_pass')
          expect(manager.active_leases[:rabbitmq][:lease_id]).to eq(vault_response.lease_id)
          expect(sys_double).not_to have_received(:revoke).with(lease_id: vault_response.lease_id)
          expect(sys_double).not_to have_received(:revoke).with(lease_id: bootstrap_lease_id)
          described_class.revoke_bootstrap_lease
          expect(sys_double).to have_received(:revoke).with(lease_id: bootstrap_lease_id)
        end
      end

      context 'when reconnect returns false despite an open session' do
        before { allow(transport_connection_double).to receive(:force_reconnect).and_return(false) }

        include_examples 'a rejected identity handoff'
      end

      context 'when reconnect returns true but the session remains closed' do
        before { allow(transport_connection_double).to receive(:session_open?).and_return(false) }

        include_examples 'a rejected identity handoff'
      end

      context 'when reconnect raises' do
        before { allow(transport_connection_double).to receive(:force_reconnect).and_raise(IOError, 'connection failed') }

        include_examples 'a rejected identity handoff'
      end

      [nil, { username: 'incomplete' }, { password: 'incomplete' }].each do |data|
        context "when the acquired candidate has incomplete credentials #{data.inspect}" do
          before { allow(identity_response).to receive(:data).and_return(data) }

          include_examples 'a rejected identity handoff'

          it 'never reconnects and retains ownership of the invalid candidate until cleanup' do
            expect { described_class.swap_to_identity_creds(mode: :agent) }.to raise_error(RuntimeError)

            expect(transport_connection_double).not_to have_received(:force_reconnect)
            manager.shutdown
            expect(sys_double).to have_received(:revoke).with(lease_id: identity_response.lease_id).at_least(:once)
          end
        end
      end
    end
  end

  describe '.revoke_bootstrap_lease' do
    it 'is a no-op when no bootstrap lease is stored' do
      described_class.instance_variable_set(:@bootstrap_lease_id, nil)
      expect(sys_double).not_to receive(:revoke)
      described_class.revoke_bootstrap_lease
    end

    it 'revokes the stored bootstrap lease' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      expect(sys_double).to receive(:revoke).with(lease_id: 'boot/lease/abc123')
      described_class.revoke_bootstrap_lease
    end

    it 'is idempotent — second call is a no-op' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      described_class.revoke_bootstrap_lease
      expect(sys_double).not_to receive(:revoke)
      described_class.revoke_bootstrap_lease
    end

    it 'propagates programming errors without discarding the lease needed for cleanup' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      failure = ArgumentError.new('invalid revocation call')
      allow(sys_double).to receive(:revoke).and_raise(failure)

      expect { described_class.revoke_bootstrap_lease }.to(raise_error { |error| expect(error).to equal(failure) })
      expect(described_class.instance_variable_get(:@bootstrap_lease_id)).to eq('boot/lease/abc123')
    end

    it 'clears bootstrap tracking after a handled timeout so the lease can expire naturally' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      described_class.instance_variable_set(:@bootstrap_lease_expires, Time.now + 300)
      allow(sys_double).to receive(:revoke).and_raise(Timeout::Error)

      described_class.revoke_bootstrap_lease

      expect(described_class.instance_variable_get(:@bootstrap_lease_id)).to be_nil
      expect(described_class.instance_variable_get(:@bootstrap_lease_expires)).to be_nil
    end
  end

  describe 'start_lease_manager with dynamic_rmq_creds guard' do
    before do
      Legion::Settings[:crypt][:vault][:connected] = true
      Legion::Settings[:crypt][:vault][:leases] = {}
    end

    after do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
      Legion::Settings[:crypt][:vault][:connected] = false
    end

    it 'keeps a renewal worker available for later dynamic leases' do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = true

      described_class.send(:start_lease_manager)

      expect(manager.renewal_thread_alive?).to be(true)
      manager.shutdown
      expect(manager.renewal_thread_alive?).to be(false)
    end

    it 'does not start a renewal worker without static or dynamic leases' do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false

      described_class.send(:start_lease_manager)

      expect(manager.renewal_thread_alive?).to be(false)
    end
  end
end
