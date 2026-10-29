# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/lease_manager'

RSpec.describe Legion::Crypt::LeaseManager do
  subject(:manager) { described_class.instance }

  let(:vault_response) do
    double('Vault::Secret',
           data:           { username: 'rabbit_user', password: 'rabbit_pass' },
           lease_id:       'rabbitmq/creds/legion-role/abc123',
           lease_duration: 3600,
           renewable?:     true)
  end

  let(:lease_definitions) do
    { 'rabbitmq' => { 'path' => 'rabbitmq/creds/legion-role' } }
  end

  before(:each) do
    manager.reset!
    allow(Vault).to receive_message_chain(:logical, :read).and_return(vault_response)
  end

  describe '#start' do
    it 'fetches each defined lease from Vault' do
      expect(Vault.logical).to receive(:read).with('rabbitmq/creds/legion-role').and_return(vault_response)
      manager.start(lease_definitions)
    end

    context 'when vault_client: is provided' do
      let(:mock_vault_client) { double('Vault::Client') }
      let(:mock_logical) { double('Vault::Logical') }

      before do
        allow(mock_vault_client).to receive(:logical).and_return(mock_logical)
        allow(mock_logical).to receive(:read).and_return(vault_response)
      end

      it 'uses the provided vault_client for reads' do
        expect(mock_logical).to receive(:read).with('rabbitmq/creds/legion-role').and_return(vault_response)
        expect(Vault).not_to receive(:logical)
        manager.start(lease_definitions, vault_client: mock_vault_client)
      end
    end

    it 'caches the lease data' do
      manager.start(lease_definitions)
      expect(manager.lease_data('rabbitmq')).to eq({ username: 'rabbit_user', password: 'rabbit_pass' })
    end

    it 'skips failed leases and keeps others empty' do
      allow(Vault).to receive_message_chain(:logical, :read).and_raise(StandardError, 'vault unavailable')
      manager.start(lease_definitions)
      expect(manager.active_leases).to be_empty
    end

    it 'is a no-op with empty definitions' do
      expect(Vault.logical).not_to receive(:read)
      manager.start({})
      expect(manager.active_leases).to be_empty
    end

    context 'when a valid lease is already cached' do
      before { manager.start(lease_definitions) }

      it 'does not create a second lease on repeated start' do
        expect(Vault.logical).not_to receive(:read)
        manager.start(lease_definitions)
      end

      it 'preserves the original cached credentials' do
        manager.start(lease_definitions)
        expect(manager.fetch('rabbitmq', :username)).to eq('rabbit_user')
      end
    end

    context 'when a cached lease is expired' do
      let(:expired_response) do
        double('Vault::Secret',
               data:           { username: 'old_user', password: 'old_pass' },
               lease_id:       'rabbitmq/creds/legion-role/expired123',
               lease_duration: 3600,
               renewable?:     true)
      end

      let(:fresh_response) do
        double('Vault::Secret',
               data:           { username: 'new_user', password: 'new_pass' },
               lease_id:       'rabbitmq/creds/legion-role/fresh456',
               lease_duration: 3600,
               renewable?:     true)
      end

      before do
        allow(Vault).to receive_message_chain(:logical, :read).and_return(expired_response)
        manager.start(lease_definitions)
        manager.active_leases['rabbitmq'][:expires_at] = Time.now - 1
        allow(Vault).to receive_message_chain(:logical, :read).and_return(fresh_response)
        allow(Vault).to receive_message_chain(:sys, :revoke)
      end

      it 'revokes the expired lease before re-fetching' do
        sys_double = instance_double(Vault::Sys)
        allow(Vault).to receive(:sys).and_return(sys_double)
        expect(sys_double).to receive(:revoke).with('rabbitmq/creds/legion-role/expired123')
        manager.start(lease_definitions)
      end

      it 'fetches new credentials when the cached lease has expired' do
        expect(Vault.logical).to receive(:read).with('rabbitmq/creds/legion-role').and_return(fresh_response)
        manager.start(lease_definitions)
      end

      it 'caches the new credentials after re-fetch' do
        manager.start(lease_definitions)
        expect(manager.fetch('rabbitmq', :username)).to eq('new_user')
      end

      it 'stores the new lease_id after re-fetch' do
        manager.start(lease_definitions)
        expect(manager.active_leases['rabbitmq'][:lease_id]).to eq('rabbitmq/creds/legion-role/fresh456')
      end
    end
  end

  describe '#fetch' do
    before { manager.start(lease_definitions) }

    it 'returns the value for a valid name and symbol key' do
      expect(manager.fetch('rabbitmq', :username)).to eq('rabbit_user')
    end

    it 'returns the value for a valid name and string key' do
      expect(manager.fetch('rabbitmq', 'username')).to eq('rabbit_user')
    end

    it 'returns nil for an unknown lease name' do
      expect(manager.fetch('unknown_lease', :username)).to be_nil
    end

    it 'returns nil for an unknown key' do
      expect(manager.fetch('rabbitmq', :nonexistent_key)).to be_nil
    end
  end

  describe '#lease_data' do
    it 'returns the full data hash for a known lease' do
      manager.start(lease_definitions)
      expect(manager.lease_data('rabbitmq')).to eq({ username: 'rabbit_user', password: 'rabbit_pass' })
    end

    it 'returns nil for an unknown lease' do
      expect(manager.lease_data('nonexistent')).to be_nil
    end
  end

  describe '#push_to_settings' do
    let(:vault_response) do
      double('Vault::Secret',
             data:           { username: 'new_user', password: 'new_pass' },
             lease_id:       'rabbitmq/creds/legion-role/def456',
             lease_duration: 3600,
             renewable?:     true)
    end

    let(:transport_settings) do
      { connection: { username: 'old_user', password: 'old_pass' },
        connections: [[{ password: 'array_old' }]], passwords: ['list_old'] }
    end

    before do
      allow(Vault).to receive_message_chain(:logical, :read).and_return(vault_response)
      manager.start({ 'rabbitmq' => { 'path' => 'rabbitmq/creds/legion-role' } })
      allow(Legion::Settings.loader).to receive(:settings).and_return(transport: transport_settings)
    end

    it 'updates settings values at registered paths' do
      connection_hash = transport_settings[:connection]
      manager.register_ref('rabbitmq', 'username', %i[transport connection username])
      manager.register_ref('rabbitmq', 'password', %i[transport connection password])
      manager.push_to_settings('rabbitmq')

      expect(connection_hash[:username]).to eq('new_user')
      expect(connection_hash[:password]).to eq('new_pass')
    end

    it 'updates every distinct typed destination for a credential' do
      manager.register_ref('rabbitmq', :password, %i[transport connection password])
      manager.register_ref(:rabbitmq, 'password', [:transport, :connections, 0, 0, :password])
      manager.register_ref('rabbitmq', :password, [:transport, :passwords, 0])
      expect(manager.push_to_settings('rabbitmq')).to eq(3)
      expect(transport_settings[:connection][:password]).to eq('new_pass')
      expect(transport_settings[:connections][0][0][:password]).to eq('new_pass')
      expect(transport_settings[:passwords]).to eq(['new_pass'])
    end

    it 'deduplicates destinations and keeps the registered path independent of its caller' do
      path = %i[transport connection password]
      manager.register_ref('rabbitmq', :password, path)
      manager.register_ref(:rabbitmq, 'password', path)
      path[-1] = :username
      expect(manager.push_to_settings('rabbitmq')).to eq(1)
      expect(transport_settings[:connection]).to eq(username: 'old_user', password: 'new_pass')
    end

    it 'rejects invalid path types, missing destinations, and out-of-bounds array indexes' do
      original = Marshal.load(Marshal.dump(transport_settings))
      [
        [:transport, :connections, -1, 0, :password],
        [:transport, :connections, 3, 0, :password],
        [:transport, :connections, '0', 0, :password],
        [:transport, :connection, 0],
        %i[transport connection missing],
        %i[transport connection password nested],
        [:transport, 'connection', :password]
      ].each { |path| manager.register_ref('rabbitmq', :password, path) }
      expect(manager.push_to_settings('rabbitmq')).to eq(0)
      expect(transport_settings).to eq(original)
    end

    it 'preserves false values while leaving missing lease-data keys untouched' do
      vault_response.data[:password] = false
      manager.register_ref('rabbitmq', :password, %i[transport connection password])
      manager.register_ref('rabbitmq', :missing, %i[transport connection username])
      expect(manager.push_to_settings('rabbitmq')).to eq(1)
      expect(transport_settings[:connection]).to eq(username: 'old_user', password: false)
    end
  end

  describe '#start_renewal_thread' do
    let(:vault_response) do
      double('Vault::Secret',
             data:           { username: 'user1', password: 'pass1' },
             lease_id:       'rabbitmq/creds/role/abc',
             lease_duration: 10,
             renewable?:     true)
    end

    before do
      allow(Vault).to receive_message_chain(:logical, :read).and_return(vault_response)
    end

    it 'starts a background thread' do
      manager.start({ 'rabbitmq' => { 'path' => 'rabbitmq/creds/legion-role' } })
      manager.start_renewal_thread
      expect(manager.renewal_thread_alive?).to eq(true)
      manager.shutdown
    end

    it 'is stopped by shutdown' do
      manager.start({ 'rabbitmq' => { 'path' => 'rabbitmq/creds/legion-role' } })
      manager.start_renewal_thread
      manager.shutdown
      sleep(0.1) # give thread time to stop
      expect(manager.renewal_thread_alive?).to eq(false)
    end

    it 'is idempotent — second call is a no-op' do
      manager.start({ 'rabbitmq' => { 'path' => 'rabbitmq/creds/legion-role' } })
      manager.start_renewal_thread
      thread1 = manager.instance_variable_get(:@renewal_thread)
      manager.start_renewal_thread
      thread2 = manager.instance_variable_get(:@renewal_thread)
      expect(thread1).to be(thread2)
      manager.shutdown
    end
  end

  describe '#lease_valid?' do
    it 'returns false when no lease exists for the name' do
      expect(manager.send(:lease_valid?, 'rabbitmq')).to be(false)
    end

    it 'returns true when the lease exists and has not expired' do
      manager.start(lease_definitions)
      expect(manager.send(:lease_valid?, 'rabbitmq')).to be(true)
    end

    it 'returns false when the lease exists but expires_at is in the past' do
      manager.start(lease_definitions)
      manager.active_leases['rabbitmq'][:expires_at] = Time.now - 1
      expect(manager.send(:lease_valid?, 'rabbitmq')).to be(false)
    end

    it 'returns false when expires_at is nil' do
      manager.start(lease_definitions)
      manager.active_leases['rabbitmq'][:expires_at] = nil
      expect(manager.send(:lease_valid?, 'rabbitmq')).to be(false)
    end
  end

  describe '#approaching_expiry?' do
    it 'returns true when past 50% of lease TTL' do
      lease = { expires_at: Time.now + 10, lease_duration: 100 }
      expect(manager.send(:approaching_expiry?, lease)).to eq(true)
    end

    it 'returns false when before 50% of lease TTL' do
      lease = { expires_at: Time.now + 80, lease_duration: 100 }
      expect(manager.send(:approaching_expiry?, lease)).to eq(false)
    end

    it 'returns true when expires_at is nil' do
      lease = { expires_at: nil, lease_duration: 100 }
      expect(manager.send(:approaching_expiry?, lease)).to eq(true)
    end
  end

  describe '#renew_lease' do
    before { manager.start(lease_definitions) }

    it 'refreshes lease_duration and renewable from the renewal response' do
      renew_response = double('Vault::Secret',
                              data:           { username: 'renewed_user', password: 'renewed_pass' },
                              lease_id:       'rabbitmq/creds/legion-role/abc123',
                              lease_duration: 1200,
                              renewable?:     false)
      sys_double = instance_double(Vault::Sys)
      allow(Vault).to receive(:sys).and_return(sys_double)
      allow(sys_double).to receive(:renew).and_return(renew_response)

      manager.send(:renew_lease, 'rabbitmq', manager.active_leases['rabbitmq'])

      expect(manager.active_leases['rabbitmq'][:lease_duration]).to eq(1200)
      expect(manager.active_leases['rabbitmq'][:renewable]).to be(false)
      expect(manager.fetch('rabbitmq', :username)).to eq('renewed_user')
    end
  end

  describe '#shutdown' do
    before { manager.start(lease_definitions) }

    it 'revokes active leases via Vault' do
      sys_double = instance_double(Vault::Sys)
      allow(Vault).to receive(:sys).and_return(sys_double)
      expect(sys_double).to receive(:revoke).with('rabbitmq/creds/legion-role/abc123')
      manager.shutdown
    end

    context 'when started with a vault_client' do
      let(:mock_vault_client) { double('Vault::Client') }
      let(:mock_logical) { double('Vault::Logical') }
      let(:mock_sys) { double('Vault::Sys') }

      before do
        manager.reset!
        allow(mock_vault_client).to receive(:logical).and_return(mock_logical)
        allow(mock_vault_client).to receive(:sys).and_return(mock_sys)
        allow(mock_logical).to receive(:read).and_return(vault_response)
        allow(mock_sys).to receive(:revoke)
        manager.start(lease_definitions, vault_client: mock_vault_client)
      end

      it 'uses the cluster vault_client to revoke leases' do
        expect(mock_sys).to receive(:revoke).with('rabbitmq/creds/legion-role/abc123')
        expect(Vault).not_to receive(:sys)
        manager.shutdown
      end
    end

    it 'clears the cache after shutdown' do
      allow(Vault).to receive_message_chain(:sys, :revoke)
      manager.shutdown
      expect(manager.active_leases).to be_empty
    end

    it 'clears lease data after shutdown' do
      allow(Vault).to receive_message_chain(:sys, :revoke)
      manager.shutdown
      expect(manager.lease_data('rabbitmq')).to be_nil
    end

    it 'skips leases with nil lease_id during shutdown' do
      nil_lease_response = double('Vault::Secret',
                                  data:           { token: 'abc' },
                                  lease_id:       nil,
                                  lease_duration: 900,
                                  renewable?:     false)
      manager.reset!
      allow(Vault).to receive_message_chain(:logical, :read).and_return(nil_lease_response)
      manager.start(lease_definitions)
      expect(Vault).not_to receive(:sys)
      manager.shutdown
    end

    it 'skips leases with empty lease_id during shutdown' do
      empty_lease_response = double('Vault::Secret',
                                    data:           { token: 'abc' },
                                    lease_id:       '',
                                    lease_duration: 900,
                                    renewable?:     false)
      manager.reset!
      allow(Vault).to receive_message_chain(:logical, :read).and_return(empty_lease_response)
      manager.start(lease_definitions)
      expect(Vault).not_to receive(:sys)
      manager.shutdown
    end
  end

  describe '#register_dynamic_lease' do
    let(:dynamic_response) do
      double('Vault::Secret',
             data:           { username: 'dyn_user', password: 'dyn_pass' },
             lease_id:       'rabbitmq/creds/legionio-infra/dyn123',
             lease_duration: 604_800,
             renewable?:     true)
    end

    it 'publishes dynamic credentials through the registered destinations' do
      transport = { connection: { user: 'old_user', password: 'old_pass' } }
      allow(Legion::Settings.loader).to receive(:settings).and_return(transport: transport)
      manager.register_dynamic_lease(
        name:          :rabbitmq,
        path:          'rabbitmq/creds/legionio-infra',
        response:      dynamic_response,
        settings_refs: [
          { path: %i[transport connection user],     key: :username },
          { path: %i[transport connection password], key: :password }
        ]
      )
      expect(manager.push_to_settings(:rabbitmq)).to eq(2)
      expect(transport[:connection]).to eq(user: 'dyn_user', password: 'dyn_pass')
    end
  end

  describe '#renew_lease with static leases' do
    let(:fresh_response) do
      double('Vault::Secret',
             data:           { username: 'fresh_user', password: 'fresh_pass' },
             lease_id:       'rabbitmq/creds/legion-role/fresh789',
             lease_duration: 3600,
             renewable?:     true)
    end

    before { manager.start(lease_definitions) }

    it 'falls back to reissue when sys.renew fails and path is available' do
      sys_double = instance_double(Vault::Sys)
      allow(Vault).to receive(:sys).and_return(sys_double)
      allow(sys_double).to receive(:renew).and_raise(StandardError, 'permission denied')
      allow(Vault).to receive_message_chain(:logical, :read).and_return(fresh_response)

      manager.send(:renew_lease, 'rabbitmq', manager.active_leases['rabbitmq'])

      expect(manager.fetch('rabbitmq', :username)).to eq('fresh_user')
    end

    it 'updates credentials after successful reissue fallback' do
      sys_double = instance_double(Vault::Sys)
      allow(Vault).to receive(:sys).and_return(sys_double)
      allow(sys_double).to receive(:renew).and_raise(StandardError, 'expired')
      allow(Vault).to receive_message_chain(:logical, :read).and_return(fresh_response)

      manager.send(:renew_lease, 'rabbitmq', manager.active_leases['rabbitmq'])

      expect(manager.active_leases['rabbitmq'][:lease_id]).to eq('rabbitmq/creds/legion-role/fresh789')
    end
  end

  describe '#renew_approaching_leases with non-renewable pathless lease' do
    let(:non_renewable_response) do
      double('Vault::Secret',
             data:           { username: 'user', password: 'pass' },
             lease_id:       'some/lease/abc',
             lease_duration: 100,
             renewable?:     false)
    end

    it 'does not raise for a non-renewable lease without a path' do
      allow(Vault).to receive_message_chain(:logical, :read).and_return(non_renewable_response)
      manager.start({ 'legacy' => { 'path' => 'some/creds/role' } })
      # Remove the path to simulate the old bug
      manager.active_leases['legacy'].delete(:path)
      manager.active_leases['legacy'][:expires_at] = Time.now + 10

      expect { manager.send(:renew_approaching_leases) }.not_to raise_error
    end
  end

  describe '#trigger_reconnect' do
    context 'when name is :rabbitmq' do
      it 'calls Transport::Connection.force_reconnect' do
        transport_conn = double('Legion::Transport::Connection')
        stub_const('Legion::Transport::Connection', transport_conn)
        expect(transport_conn).to receive(:force_reconnect)
        manager.send(:trigger_reconnect, :rabbitmq)
      end
    end

    context 'when name is :postgresql' do
      context 'when reconnect_with_fresh_creds is available' do
        it 'calls reconnect_with_fresh_creds' do
          data_mod = Module.new
          connection_mod = double('Legion::Data::Connection')
          stub_const('Legion::Data', data_mod)
          stub_const('Legion::Data::Connection', connection_mod)
          allow(connection_mod).to receive(:respond_to?).with(:reconnect_with_fresh_creds).and_return(true)
          expect(connection_mod).to receive(:reconnect_with_fresh_creds).and_return(true)
          manager.send(:trigger_reconnect, :postgresql)
        end

        it 'logs error when reconnect_with_fresh_creds returns false' do
          data_mod = Module.new
          connection_mod = double('Legion::Data::Connection')
          stub_const('Legion::Data', data_mod)
          stub_const('Legion::Data::Connection', connection_mod)
          allow(connection_mod).to receive(:respond_to?).with(:reconnect_with_fresh_creds).and_return(true)
          allow(connection_mod).to receive(:reconnect_with_fresh_creds).and_return(false)
          expect { manager.send(:trigger_reconnect, :postgresql) }.not_to raise_error
        end
      end

      context 'when reconnect_with_fresh_creds is not available (legacy)' do
        it 'falls back to disconnect + test_connection' do
          data_mod = Module.new
          sequel_db = double('Sequel::Database')
          connection_mod = double('Legion::Data::Connection')
          stub_const('Legion::Data', data_mod)
          stub_const('Legion::Data::Connection', connection_mod)
          allow(connection_mod).to receive(:respond_to?).with(:reconnect_with_fresh_creds).and_return(false)
          allow(connection_mod).to receive(:respond_to?).with(:sequel).and_return(true)
          allow(connection_mod).to receive(:sequel).and_return(sequel_db)
          expect(sequel_db).to receive(:disconnect)
          expect(sequel_db).to receive(:test_connection)
          manager.send(:trigger_reconnect, :postgresql)
        end
      end

      it 'logs when Legion::Data::Connection is not defined' do
        expect(manager.log).to receive(:debug).with("LeaseManager: no Legion::Data::Connection loaded for 'postgresql' reconnect")

        expect { manager.send(:trigger_reconnect, :postgresql) }.not_to raise_error
      end
    end

    context 'when name is :redis' do
      it 'calls Cache.restart when available' do
        cache_mod = double('Legion::Cache')
        stub_const('Legion::Cache', cache_mod)
        allow(cache_mod).to receive(:respond_to?).with(:restart).and_return(true)
        expect(cache_mod).to receive(:restart)
        manager.send(:trigger_reconnect, :redis)
      end
    end

    it 'handles reconnect errors gracefully' do
      transport_conn = double('Legion::Transport::Connection')
      stub_const('Legion::Transport::Connection', transport_conn)
      allow(transport_conn).to receive(:force_reconnect).and_raise(StandardError, 'connection refused')
      expect { manager.send(:trigger_reconnect, :rabbitmq) }.not_to raise_error
    end
  end

  describe '#reissue_lease' do
    let(:original_response) do
      double('Vault::Secret',
             data:           { username: 'orig_user', password: 'orig_pass' },
             lease_id:       'rabbitmq/creds/legionio-infra/orig111',
             lease_duration: 604_800,
             renewable?:     true)
    end

    let(:reissued_response) do
      double('Vault::Secret',
             data:           { username: 'new_user', password: 'new_pass' },
             lease_id:       'rabbitmq/creds/legionio-infra/new222',
             lease_duration: 604_800,
             renewable?:     true)
    end

    before do
      allow(Vault).to receive_message_chain(:logical, :read).and_return(reissued_response)
      manager.register_dynamic_lease(
        name:          :rabbitmq,
        path:          'rabbitmq/creds/legionio-infra',
        response:      original_response,
        settings_refs: []
      )
    end

    it 'reads from the stored path' do
      logical_double = double('Vault::Logical')
      allow(Vault).to receive(:logical).and_return(logical_double)
      expect(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra').and_return(reissued_response)
      manager.reissue_lease(:rabbitmq)
    end

    it 'updates the lease cache with new credentials' do
      manager.reissue_lease(:rabbitmq)
      expect(manager.fetch(:rabbitmq, :username)).to eq('new_user')
    end

    it 'updates the lease_id in active_leases' do
      manager.reissue_lease(:rabbitmq)
      expect(manager.active_leases[:rabbitmq][:lease_id]).to eq('rabbitmq/creds/legionio-infra/new222')
    end

    it 'updates the expires_at in active_leases' do
      before_call = Time.now
      manager.reissue_lease(:rabbitmq)
      expect(manager.active_leases[:rabbitmq][:expires_at]).to be >= before_call
    end

    it 'updates lease_duration in active_leases from the reissued response' do
      manager.reissue_lease(:rabbitmq)
      expect(manager.active_leases[:rabbitmq][:lease_duration]).to eq(604_800)
    end

    it 'updates renewable in active_leases from the reissued response' do
      manager.reissue_lease(:rabbitmq)
      expect(manager.active_leases[:rabbitmq][:renewable]).to be(true)
    end

    it 'does not raise when the active_leases entry is removed before the synchronize block runs' do
      # Simulate the entry being removed (e.g. during shutdown) between the initial read and the merge
      allow(Vault).to receive_message_chain(:logical, :read).and_return(reissued_response) do
        manager.instance_variable_get(:@active_leases).delete(:rabbitmq)
        reissued_response
      end
      expect { manager.reissue_lease(:rabbitmq) }.not_to raise_error
    end

    it 'updates fetched_at in active_leases' do
      before_call = Time.now
      manager.reissue_lease(:rabbitmq)
      expect(manager.active_leases[:rabbitmq][:fetched_at]).to be >= before_call
    end

    it 'returns early for an unknown lease name' do
      expect { manager.reissue_lease(:unknown_lease) }.not_to raise_error
    end

    it 'returns early for a lease without a path' do
      manager.active_leases[:rabbitmq].delete(:path)
      expect(Vault.logical).not_to receive(:read)
      manager.reissue_lease(:rabbitmq)
    end

    it 'returns early when Vault returns nil' do
      allow(Vault).to receive_message_chain(:logical, :read).and_return(nil)
      expect { manager.reissue_lease(:rabbitmq) }.not_to raise_error
    end

    it 'handles StandardError gracefully without raising' do
      allow(Vault).to receive_message_chain(:logical, :read).and_raise(StandardError, 'network error')
      expect { manager.reissue_lease(:rabbitmq) }.not_to raise_error
    end

    context 'when name is :rabbitmq and Transport::Connection is defined' do
      let(:transport_conn_double) { double('Legion::Transport::Connection') }

      before do
        stub_const('Legion::Transport::Connection', transport_conn_double)
        allow(transport_conn_double).to receive(:force_reconnect)
      end

      it 'calls force_reconnect on Transport::Connection' do
        expect(transport_conn_double).to receive(:force_reconnect)
        manager.reissue_lease(:rabbitmq)
      end
    end

    context 'when name is not :rabbitmq' do
      let(:kv_response) do
        double('Vault::Secret',
               data:           { token: 'new_token' },
               lease_id:       'kv/some/path/token333',
               lease_duration: 3600,
               renewable?:     true)
      end

      before do
        allow(Vault).to receive_message_chain(:logical, :read).and_return(kv_response)
        manager.register_dynamic_lease(
          name:          :kv_token,
          path:          'kv/some/path',
          response:      double('Vault::Secret',
                                data:           { token: 'old_token' },
                                lease_id:       'kv/some/path/old111',
                                lease_duration: 3600,
                                renewable?:     true),
          settings_refs: []
        )
      end

      it 'does not call force_reconnect for non-rabbitmq leases' do
        transport_conn = double('Legion::Transport::Connection')
        stub_const('Legion::Transport::Connection', transport_conn)
        expect(transport_conn).not_to receive(:force_reconnect)
        manager.reissue_lease(:kv_token)
      end
    end
  end

  describe 'bounded lifecycle operations' do
    let(:configuration) { Legion::Crypt::Settings.default }
    let(:connection) { { username: 'original' } }
    let(:sys) { double('Vault sys', revoke: nil) }
    let(:fresh_response) do
      double('fresh lease', data: { username: 'fresh' }, lease_id: 'fresh-id', lease_duration: 3600, renewable?: true)
    end

    before do
      configuration[:vault][:operation_timeout] = 0.02
      allow(Legion::Settings).to receive(:[]).and_call_original
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
      allow(Legion::Settings.loader).to receive(:settings).and_return(transport: { connection: connection })
      allow(Vault).to receive(:sys).and_return(sys)
    end

    after { manager.reset! }

    it 'continues acquisition after a stalled lease read times out' do
      allow(Vault.logical).to receive(:read) do |path|
        sleep(10) if path == 'slow'
        fresh_response
      end
      Timeout.timeout(1) { manager.start({ 'slow' => { path: 'slow' }, 'healthy' => { path: 'healthy' } }) }
      expect(manager.fetch('slow', :username)).to be_nil
      expect(manager.fetch('healthy', :username)).to eq('fresh')
    end

    it 'continues renewal after one lease times out' do
      manager.start({ 'slow' => { path: 'slow' } })
      allow(Vault.logical).to receive(:read).and_return(fresh_response)
      manager.start({ 'healthy' => { path: 'healthy' } })
      manager.active_leases.each_value { |lease| lease[:expires_at] = Time.now }
      allow(sys).to receive(:renew) do |lease_id|
        sleep(10) if lease_id == vault_response.lease_id
        fresh_response
      end

      Timeout.timeout(1) { manager.send(:renew_approaching_leases) }
      expect(manager.active_leases['healthy'][:expires_at]).to be > Time.now
      expect(manager.fetch('healthy', :username)).to eq('fresh')
    end

    it 'does not let a late renewal overwrite restarted cache or settings' do
      configuration[:vault][:operation_timeout] = 2
      manager.start(lease_definitions)
      manager.register_ref('rabbitmq', :username, %i[transport connection username])
      entered = Queue.new
      release = Queue.new
      allow(sys).to receive(:renew) do
        entered << true
        release.pop
        vault_response
      end
      snapshot = manager.active_leases['rabbitmq'].dup
      worker = Thread.new { manager.send(:renew_lease, 'rabbitmq', snapshot) }
      Timeout.timeout(1) { entered.pop }
      manager.shutdown
      allow(Vault.logical).to receive(:read).and_return(fresh_response)
      manager.start(lease_definitions)
      manager.register_ref('rabbitmq', :username, %i[transport connection username])
      manager.push_to_settings('rabbitmq')
      release << true
      Timeout.timeout(1) { worker.join }

      expect(manager.fetch('rabbitmq', :username)).to eq('fresh')
      expect(connection[:username]).to eq('fresh')
    ensure
      worker&.kill
      worker&.join
    end

    it 'discards a reissue when its initiating token lifecycle stops' do
      configuration[:vault][:operation_timeout] = 2
      manager.start(lease_definitions)
      manager.register_ref('rabbitmq', :username, %i[transport connection username])
      guard = Mutex.new
      running = true
      active = lambda do |&mutation|
        guard.synchronize do
          next false unless running

          mutation&.call
          true
        end
      end
      entered = Queue.new
      release = Queue.new
      allow(Vault.logical).to receive(:read) do
        entered << true
        release.pop
        fresh_response
      end
      worker = Thread.new { manager.reissue_all(active: active) }
      Timeout.timeout(1) { entered.pop }
      guard.synchronize { running = false }
      release << true
      Timeout.timeout(1) { worker.join }

      expect(manager.fetch('rabbitmq', :username)).to eq('rabbit_user')
      expect(connection[:username]).to eq('original')
    ensure
      worker&.kill
      worker&.join
    end

    it 'detaches state and continues revocation after a stalled lease' do
      manager.start({ 'slow' => { path: 'slow' } })
      allow(Vault.logical).to receive(:read).and_return(fresh_response)
      manager.start({ 'healthy' => { path: 'healthy' } })
      revoked = []
      allow(sys).to receive(:revoke) do |lease_id|
        sleep(10) if lease_id == vault_response.lease_id
        revoked << lease_id
      end
      Timeout.timeout(1) { manager.shutdown }
      expect(revoked).to eq(['fresh-id'])
      expect(manager.fetch('slow', :username)).to be_nil
      expect(manager.fetch('healthy', :username)).to be_nil
    end
  end
end
