# frozen_string_literal: true

require 'spec_helper'
require 'concurrent'

require 'legion/crypt/vault'

RSpec.describe Legion::Crypt::Vault do
  let(:vault_sys) { instance_double(Legion::Crypt::VaultClient::Sys) }
  let(:default_client) do
    instance_double(Legion::Crypt::VaultClient, sys: vault_sys, address: 'https://vault.example.com', namespace: nil, ssl_verify: true)
  end

  before do
    @vault = Class.new
    @vault.extend Legion::Crypt::VaultCluster
    @vault.define_singleton_method(:vault_settings) { Legion::Settings[:crypt][:vault] }
    @vault.extend Legion::Crypt::Vault
    @vault.sessions = []
    allow(@vault).to receive(:vault_client).and_return(default_client)
  end

  describe '#connect_vault rescue logging' do
    before do
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]).and_call_original
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]).with(:token).and_return('test-token')
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]=)
      allow(vault_sys).to receive(:health_status).and_raise(StandardError, 'connection refused')
    end

    it 'returns false and does not raise when Vault.sys.health_status raises' do
      expect(@vault.connect_vault).to eq false
    end

    it 'logs the exception via handle_exception' do
      expect(@vault).to receive(:handle_exception).with(instance_of(StandardError), hash_including(level: :error))
      @vault.connect_vault
    end
  end

  describe 'session lifecycle' do
    before do
      @original_operation_timeout = Legion::Settings[:crypt][:vault][:operation_timeout]
      Legion::Settings[:crypt][:vault][:operation_timeout] = 0.02
      allow(Legion::Crypt).to receive(:stopping).and_return(false)
    end

    after do
      Legion::Settings[:crypt][:vault][:operation_timeout] = @original_operation_timeout
    end

    it 'revokes later sessions after a failure and reports only completed revocations' do
      @vault.add_session(path: 'failed')
      @vault.add_session(path: 'healthy')
      revoked = []
      allow(vault_sys).to receive(:revoke) do |lease_id:|
        raise IOError, 'unavailable' if lease_id == 'failed'

        revoked << lease_id
        nil
      end
      expect(@vault).to receive(:handle_exception).with(instance_of(IOError), hash_including(level: :error))

      expect(@vault.close_sessions).to eq(['healthy'])
      expect(revoked).to eq(['healthy'])
      expect(@vault.sessions).to eq([])
      expect(@vault.close_sessions).to eq([])
      expect(revoked).to eq(['healthy'])
    end

    it 'bounds a stalled revocation before continuing with a healthy session' do
      @vault.sessions = %w[stalled healthy]
      revoked = []
      allow(vault_sys).to receive(:revoke) do |lease_id:|
        sleep 5 if lease_id == 'stalled'
        revoked << lease_id
      end
      expect(@vault).to receive(:handle_exception).with(instance_of(Timeout::Error), hash_including(level: :error))
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      expect(@vault.close_sessions).to eq(['healthy'])
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1
      expect(revoked).to eq(['healthy'])
    end

    it 'stops all cleanup at the shared deadline rather than granting each session a fresh budget' do
      Legion::Settings[:crypt][:vault][:operation_timeout] = 1
      @vault.sessions = %w[stalled later]
      attempted = []
      allow(vault_sys).to receive(:revoke) do |lease_id:|
        attempted << lease_id
        sleep 5
      end
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      expect(@vault.close_sessions(deadline: started + 0.04)).to eq([])
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1
      expect(attempted).to eq(['stalled'])
      expect(@vault.sessions).to eq([])
      expect(@vault.close_sessions).to eq([])
    end

    it 'applies a whole-close deadline even when the caller supplies none' do
      stub_const('Legion::Crypt::VaultOperation::SHUTDOWN_TIMEOUT', 0.04)
      Legion::Settings[:crypt][:vault][:operation_timeout] = 1
      @vault.sessions = %w[stalled later]
      attempted = []
      allow(vault_sys).to receive(:revoke) do |lease_id:|
        attempted << lease_id
        sleep 5
      end
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      expect(@vault.close_sessions).to eq([])
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1
      expect(attempted).to eq(['stalled'])
    end

    it 'detaches sessions before revocation and refuses late tracking without holding a network lock' do
      @vault.add_session(path: 'active')
      observed_sessions = nil
      allow(vault_sys).to receive(:revoke) do
        observed_sessions = @vault.sessions.dup
        @vault.add_session(path: 'late')
        @vault.close_sessions
      end

      expect(@vault.close_sessions).to eq(['active'])
      expect(observed_sessions).to eq([])
      expect(@vault.sessions).to eq([])
    end

    it 'refuses session tracking and renewal while Crypt is stopping' do
      @vault.sessions = ['active']
      allow(Legion::Crypt).to receive(:stopping).and_return(true)
      expect(vault_sys).not_to receive(:renew)

      @vault.add_session(path: 'late')

      expect(@vault.sessions).to eq(['active'])
      expect(@vault.renew_sessions).to eq([])
    end

    it 'keeps session maintenance stopped after the global shutdown flag clears' do
      @vault.sessions = ['active']
      allow(vault_sys).to receive(:revoke)
      @vault.close_sessions
      @vault.add_session(path: 'late')
      expect(vault_sys).not_to receive(:renew)

      expect(@vault.sessions).to eq([])
      expect(@vault.renew_sessions).to eq([])
    end

    it 'cancels a scheduled renewer even when Vault is disconnected' do
      timer = Concurrent::ScheduledTask.execute(3600) { @vault.renew_sessions }
      @vault.instance_variable_set(:@renewer, timer)
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]).and_call_original
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]).with(:connected).and_return(false)

      @vault.shutdown_renewer
      @vault.shutdown_renewer

      expect { timer.value!(0) }.to raise_error(Concurrent::CancelledOperationError)
    ensure
      timer&.cancel
    end

    it 'isolates stalled and failed lease renewals from later healthy work' do
      @vault.sessions = %w[stalled failed healthy]
      renewed = []
      allow(vault_sys).to receive(:renew) do |lease_id:|
        sleep 5 if lease_id == 'stalled'
        raise IOError, 'unavailable' if lease_id == 'failed'

        renewed << lease_id
      end
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      expect(@vault.renew_sessions).to eq(['healthy'])
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1
      expect(renewed).to eq(['healthy'])
    end

    it 'does not renew the remaining snapshot after shutdown starts during a renewal' do
      @vault.sessions = %w[first later]
      renewed = []
      allow(vault_sys).to receive(:renew) do |lease_id:|
        renewed << lease_id
        @vault.shutdown_renewer
      end

      @vault.renew_sessions

      expect(renewed).to eq(['first'])
      expect(@vault.renew_sessions).to eq([])
    end

    it 'does not resume an old renewal snapshot when session tracking restarts' do
      @vault.sessions = %w[first obsolete]
      renewed = []
      allow(vault_sys).to receive(:renew) do |lease_id:|
        renewed << lease_id
        if lease_id == 'first'
          @vault.shutdown_renewer
          @vault.start_session_tracking
          @vault.add_session(path: 'new')
        end
      end

      @vault.renew_sessions
      @vault.renew_sessions

      expect(renewed).to eq(%w[first new])
      expect(@vault.sessions).to eq(['new'])
    end

    it 'bounds each cluster token renewal while preserving routing and failure isolation' do
      @vault.extend(Legion::Crypt::VaultCluster)
      allow(@vault).to receive(:connected_clusters).and_return(stalled: {}, failed: {}, healthy: {})
      renewed = []
      %i[stalled failed healthy].each do |name|
        token = double("token-#{name}")
        client = instance_double(Legion::Crypt::VaultClient, auth_token: token)
        allow(@vault).to receive(:vault_client).with(name).and_return(client)
        allow(token).to receive(:renew_self) do
          sleep 5 if name == :stalled
          raise IOError, 'unavailable' if name == :failed

          renewed << name
        end
      end
      expect(default_client).not_to receive(:auth_token)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      expect(@vault.renew_sessions).to eq([:healthy])
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1
      expect(renewed).to eq([:healthy])
    end
  end

  # Multi-cluster KV routing: kv_client / logical_client helpers
  #
  # The test object extends both Vault and VaultCluster so that connected_clusters
  # and vault_client are available, mirroring how Legion::Crypt composes them.
  describe 'multi-cluster client routing' do
    before do
      @original_kv_path = Legion::Settings[:crypt][:vault][:kv_path]
      Legion::Settings[:crypt][:vault][:kv_path] = kv_path
    end

    after { Legion::Settings[:crypt][:vault][:kv_path] = @original_kv_path }

    let(:kv_path) { 'legion' }
    let(:mock_kv)      { double('kv') }
    let(:mock_logical) { double('logical') }
    let(:mock_cluster_client) do
      dbl = instance_double(Legion::Crypt::VaultClient)
      allow(dbl).to receive(:kv).with(mount: kv_path).and_return(mock_kv)
      allow(dbl).to receive(:logical).and_return(mock_logical)
      dbl
    end

    # A host object that mixes in both modules so connected_clusters and
    # vault_client are available alongside the Vault KV methods.
    let(:host) do
      obj = Object.new
      obj.extend(Legion::Crypt::VaultCluster)
      obj.extend(Legion::Crypt::Vault)
      obj.define_singleton_method(:vault_settings) { { clusters: {} } }
      obj.sessions = []
      obj
    end

    context 'when clusters are connected' do
      before do
        allow(host).to receive(:connected_clusters).and_return({ primary: { token: 'tok', connected: true } })
        allow(host).to receive(:selected_connected_cluster_name).with(nil).and_return(:primary)
        allow(host).to receive(:vault_client).with(:primary).and_return(mock_cluster_client)
      end

      describe '#get' do
        it 'reads through the cluster kv client' do
          secret = double('secret', data: { value: 'secret_val' })
          allow(mock_kv).to receive(:read).with(path: 'mypath').and_return(secret)
          result = host.get('mypath')
          expect(result).to eq({ value: 'secret_val' })
        end

        it 'returns nil when the cluster kv client returns nil' do
          allow(mock_kv).to receive(:read).with(path: 'missing').and_return(nil)
          expect(host.get('missing')).to be_nil
        end
      end

      describe '#write' do
        it 'writes through the cluster kv client' do
          expect(mock_kv).to receive(:write).with(path: 'mypath', data: { key: 'val' })
          host.write('mypath', key: 'val')
        end
      end

      describe '#exist?' do
        it 'reads metadata through the cluster kv client' do
          allow(mock_kv).to receive(:read_metadata).with(path: 'mypath').and_return(double('meta'))
          expect(host.exist?('mypath')).to be true
        end

        it 'returns false when metadata is nil' do
          allow(mock_kv).to receive(:read_metadata).with(path: 'gone').and_return(nil)
          expect(host.exist?('gone')).to be false
        end
      end

      describe '#delete' do
        it 'deletes through the cluster logical client' do
          allow(mock_logical).to receive(:delete).with(path: 'secret/mypath').and_return(nil)
          result = host.delete('secret/mypath')
          expect(result[:success]).to be true
        end

        it 'returns success: false on error' do
          allow(mock_logical).to receive(:delete).and_raise(StandardError, 'permission denied')
          result = host.delete('secret/mypath')
          expect(result[:success]).to be false
          expect(result[:error]).to match(/permission denied/)
        end
      end

      describe '#read (logical)' do
        it 'reads through the cluster logical client' do
          lease = double('lease', lease_id: nil, data: { token: 'abc' })
          allow(lease).to receive(:respond_to?).with(:lease_id).and_return(false)
          allow(mock_logical).to receive(:read).and_return(lease)
          result = host.read('database/creds/myrole', nil)
          expect(result).to eq({ token: 'abc' })
        end
      end

      describe 'explicit cluster selection' do
        let(:mock_secondary_kv) { double('kv-secondary') }
        let(:mock_secondary_logical) { double('logical-secondary') }
        let(:mock_secondary_client) do
          dbl = instance_double(Legion::Crypt::VaultClient)
          allow(dbl).to receive(:kv).with(mount: kv_path).and_return(mock_secondary_kv)
          allow(dbl).to receive(:logical).and_return(mock_secondary_logical)
          dbl
        end

        before do
          allow(host).to receive(:connected_clusters).and_return(
            {
              primary:   { token: 'tok', connected: true },
              secondary: { token: 'tok-2', connected: true }
            }
          )
          allow(host).to receive(:selected_connected_cluster_name).with(:secondary).and_return(:secondary)
          allow(host).to receive(:vault_client).with(:secondary).and_return(mock_secondary_client)
        end

        it 'routes get through the requested cluster client' do
          secret = double('secret', data: { value: 'secondary' })
          allow(mock_secondary_kv).to receive(:read).with(path: 'mypath').and_return(secret)

          expect(host.get('mypath', cluster_name: :secondary)).to eq({ value: 'secondary' })
        end

        it 'raises when the requested cluster is not connected' do
          allow(host).to receive(:selected_connected_cluster_name).with(:missing)
                     .and_raise(ArgumentError, 'Vault cluster not connected: missing')

          expect do
            host.get('mypath', cluster_name: :missing)
          end.to raise_error(ArgumentError, /not connected/)
        end
      end
    end

    context 'when no clusters are configured' do
      before do
        allow(host).to receive(:connected_clusters).and_return({})
      end

      let(:global_kv)      { double('global_kv') }
      let(:global_logical) { double('global_logical') }

      before do
        allow(host).to receive(:vault_client).and_return(default_client)
        allow(default_client).to receive(:kv).with(mount: kv_path).and_return(global_kv)
        allow(default_client).to receive(:logical).and_return(global_logical)
      end

      describe '#get' do
        it 'reads through the default core client' do
          secret = double('secret', data: { val: 1 })
          allow(global_kv).to receive(:read).with(path: 'mypath').and_return(secret)
          expect(host.get('mypath')).to eq({ val: 1 })
        end
      end

      describe '#write' do
        it 'writes through the default core client' do
          expect(global_kv).to receive(:write).with(path: 'mypath', data: { x: 1 })
          host.write('mypath', x: 1)
        end
      end

      describe '#exist?' do
        it 'checks metadata through the default core client' do
          allow(global_kv).to receive(:read_metadata).with(path: 'mypath').and_return(double('meta'))
          expect(host.exist?('mypath')).to be true
        end
      end
    end
  end
end

RSpec.describe Legion::Crypt, 'configured KV mounts' do
  [false, true].each do |clustered|
    it "round trips secrets on the configured mount with clustered=#{clustered}" do
      configuration = { vault: { kv_path: 'private', default: :primary } }
      allow(Legion::Settings).to receive(:[]).and_call_original
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
      allow(described_class).to receive(:connected_clusters).and_return(clustered ? { primary: { connected: true } } : {})
      endpoint = instance_double(Legion::Crypt::VaultClient)
      allow(described_class).to receive(:vault_client).and_return(endpoint)
      mounts = { 'private' => {}, nil => {} }
      clients = mounts.transform_values do |records|
        kv = double('mounted KV store')
        allow(kv).to receive(:write) { |path:, data:| records[path] = data }
        allow(kv).to receive(:read) { |path:| records.key?(path) ? double(data: records[path]) : nil }
        allow(kv).to receive(:read_metadata) { |path:| records.key?(path) ? { version: 1 } : nil }
        kv
      end
      allow(endpoint).to receive(:kv) { |mount:| clients.fetch(mount) }

      expect(described_class.exist?('worker')).to be(false)
      described_class.write('worker', password: 'fixture-secret')
      expect(described_class.get('worker')).to eq(password: 'fixture-secret')
      expect(described_class.exist?('worker')).to be(true)
      expect(mounts['private']).to eq('worker' => { password: 'fixture-secret' })
      expect(mounts[nil]).to be_empty
    end
  end
end
