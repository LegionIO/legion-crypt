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

  describe 'failure-isolated shutdown' do
    let(:configuration) do
      Legion::Crypt::Settings.default.merge(save_private_key: false, vault: Legion::Crypt::Settings.vault.merge(token: nil))
    end

    before do
      described_class.shutdown
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

    it 'revokes tracked sessions while the token is still valid and reports a token that was not revoked' do
      order = []
      sys = double('Vault sys')
      allow(described_class).to receive(:vault_client).and_return(double('core Vault client', sys: sys))
      allow(sys).to receive(:revoke) { |lease_id:| order << lease_id }
      session = instance_double(Legion::Crypt::Vault::Session, request_stop: nil)
      allow(session).to receive(:stop) do
        order << :session_token
        false
      end
      logger = double('logger').as_null_object
      allow(described_class).to receive(:log).and_return(logger)

      described_class.start
      described_class.instance_variable_set(:@vault_sessions, { nil => session })
      described_class.add_session(path: 'tracked')
      described_class.shutdown

      expect(order).to eq(['tracked', :session_token])
      expect(logger).to have_received(:error).with(/incomplete Vault cleanup: stop_vault_sessions/)
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

  describe '.jwt_login' do
    let(:jwt_grant) do
      Legion::Crypt::Vault::Client::Auth.new(data: { client_token: 'jwt-vault-token', lease_duration: 3600,
                                                     renewable: false })
    end
    let(:jwt_strategy) { instance_double(Legion::Crypt::Vault::Auth::JWT, authenticate: jwt_grant, can_reauth?: false) }
    let(:jwt_session) { Legion::Crypt::Vault::Session.new(cluster_name: :jwt_cluster, client: described_class.vault_client(:jwt_cluster)) }

    before do
      configuration = Legion::Crypt::Settings.default
      configuration[:vault][:clusters] = {
        jwt_cluster:      { auth_method: 'jwt', token: nil, jwt: { auth_path: 'auth/jwt/login', role: 'worker' } },
        kerberos_cluster: { auth_method: 'kerberos', token: nil }
      }
      Legion::Settings.set_prop(:crypt, configuration)
      allow(Legion::Crypt::Vault::Auth::JWT).to receive(:new).and_return(jwt_strategy)
      allow(Thread).to receive(:new).and_return(instance_double(Thread, alive?: true, :name= => nil, join: nil))
      allow(described_class).to receive(:revoke_vault_token)
      jwt_session.start
      described_class.instance_variable_set(:@vault_sessions, { jwt_cluster: jwt_session })
    end

    after do
      described_class.instance_variable_set(:@vault_sessions, {})
      described_class.clear_vault_clients
    end

    it 'logs in the JWT cluster and reports it connected without touching Kerberos' do
      grant = described_class.jwt_login(cluster_name: :jwt_cluster, jwt: 'signed-jwt', trace_id: 'ignored')

      expect(grant).to include(token: 'jwt-vault-token', renewable: false)
      expect(jwt_strategy).to have_received(:authenticate).with(client: jwt_session.client, jwt: 'signed-jwt')
      expect(Legion::Settings[:crypt][:vault][:clusters][:jwt_cluster][:connected]).to be(true)
      expect(described_class.connected_clusters.keys).to eq([:jwt_cluster])
      expect(Legion::Settings[:crypt][:vault][:clusters][:kerberos_cluster][:token]).to be_nil
      expect(jwt_session.send(:maintain_token)).to eq(:pending)
    end

    it 'marks an expired nonrenewable JWT grant as requiring login without Kerberos fallback' do
      described_class.jwt_login(cluster_name: :jwt_cluster, jwt: 'signed-jwt')
      jwt_session.instance_variable_set(:@expires_at, Time.now - 1)

      expect(jwt_session.send(:maintain_token)).to eq(:finished)
      expect(Legion::Settings[:crypt][:vault][:clusters][:jwt_cluster][:relogin_required]).to be(true)
      expect(Legion::Settings[:crypt][:vault][:clusters][:jwt_cluster][:connected]).to be(false)
    end

    it 'renews a JWT grant only when Vault marks it renewable' do
      renewable_grant = Legion::Crypt::Vault::Client::Auth.new(data: {
                                                                 client_token: 'jwt-vault-token', lease_duration: 3600, renewable: true
                                                               })
      allow(jwt_strategy).to receive(:authenticate).and_return(renewable_grant)
      auth_token = double('auth token', renew_self: double('secret', auth: renewable_grant))
      allow(jwt_session.client).to receive(:auth_token).and_return(auth_token)

      described_class.jwt_login(cluster_name: :jwt_cluster, jwt: 'signed-jwt')

      expect(jwt_session.send(:maintain_token)).to eq(:renewed)
      expect(auth_token).to have_received(:renew_self).once
    end

    it 'raises a rejected JWT and reports the authentication error once' do
      allow(jwt_strategy).to receive(:authenticate).and_raise(Legion::Crypt::Vault::Auth::AuthError, 'denied')
      expect(described_class).to receive(:handle_exception).once.with(
        instance_of(Legion::Crypt::Vault::Auth::AuthError), level: :error,
        operation: 'crypt.jwt_login', cluster_name: :jwt_cluster
      )

      expect { described_class.jwt_login(cluster_name: :jwt_cluster, jwt: 'rejected-jwt') }
        .to raise_error(Legion::Crypt::Vault::Auth::AuthError)
    end

    it 'raises for an unconfigured cluster' do
      expect { described_class.jwt_login(cluster_name: :missing, jwt: 'signed-jwt') }.to raise_error(KeyError)
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
    manager.reset!
    allow(Legion::Crypt).to receive(:vault_client).and_return(vault_client)
    allow(logical_double).to receive(:read).and_return(vault_response)
    allow(sys_double).to receive(:revoke).and_return(true)
    @transport_settings = Legion::Settings.loader.settings[:transport]
    Legion::Settings.loader.settings[:transport] = { connection: { vhost: '/' } }
    described_class.instance_variable_set(:@bootstrap_lease_id, nil)
    described_class.instance_variable_set(:@bootstrap_lease_expires, nil)
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
        manager.start(definitions: { 'rabbitmq' => { path: 'rabbitmq/creds/previous' } }, client: vault_client)
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
end
