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

  describe '.instance' do
    it 'returns the same object on repeated calls' do
      expect(described_class.instance).to be(described_class.instance)
    end
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

      it 'stores the vault_client for use by sys operations' do
        manager.start(lease_definitions, vault_client: mock_vault_client)
        expect(manager.instance_variable_get(:@vault_client)).to eq(mock_vault_client)
      end
    end

    it 'caches the lease data' do
      manager.start(lease_definitions)
      expect(manager.lease_data('rabbitmq')).to eq({ username: 'rabbit_user', password: 'rabbit_pass' })
    end

    it 'tracks lease metadata with lease_id' do
      manager.start(lease_definitions)
      meta = manager.active_leases['rabbitmq']
      expect(meta[:lease_id]).to eq('rabbitmq/creds/legion-role/abc123')
    end

    it 'tracks lease metadata with renewable flag' do
      manager.start(lease_definitions)
      meta = manager.active_leases['rabbitmq']
      expect(meta[:renewable]).to be(true)
    end

    it 'tracks lease metadata with lease_duration' do
      manager.start(lease_definitions)
      meta = manager.active_leases['rabbitmq']
      expect(meta[:lease_duration]).to eq(3600)
    end

    it 'tracks lease metadata with expires_at as a Time' do
      before_start = Time.now
      manager.start(lease_definitions)
      meta = manager.active_leases['rabbitmq']
      expect(meta[:expires_at]).to be_a(Time)
      expect(meta[:expires_at]).to be >= (before_start + 3600)
    end

    it 'handles Vault read failure gracefully without raising' do
      allow(Vault).to receive_message_chain(:logical, :read).and_raise(StandardError, 'vault unavailable')
      expect { manager.start(lease_definitions) }.not_to raise_error
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

  describe '#register_ref' do
    it 'stores a settings path reference without error' do
      expect { manager.register_ref('rabbitmq', :username, 'transport.connection.username') }.not_to raise_error
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

    before do
      allow(Vault).to receive_message_chain(:logical, :read).and_return(vault_response)
      manager.start({ 'rabbitmq' => { 'path' => 'rabbitmq/creds/legion-role' } })
    end

    it 'updates settings values at registered paths' do
      connection_hash = { username: 'old_user', password: 'old_pass' }
      transport_hash = { connection: connection_hash }
      allow(Legion::Settings).to receive(:[]).with(:transport).and_return(transport_hash)

      manager.register_ref('rabbitmq', 'username', %i[transport connection username])
      manager.register_ref('rabbitmq', 'password', %i[transport connection password])
      manager.push_to_settings('rabbitmq')

      expect(connection_hash[:username]).to eq('new_user')
      expect(connection_hash[:password]).to eq('new_pass')
    end

    it 'does nothing when no refs are registered for the lease' do
      expect { manager.push_to_settings('rabbitmq') }.not_to raise_error
    end

    it 'does nothing for an unknown lease name' do
      expect { manager.push_to_settings('unknown') }.not_to raise_error
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

    it 'handles revocation failure gracefully without raising' do
      allow(Vault).to receive_message_chain(:sys, :revoke).and_raise(StandardError, 'revoke failed')
      expect { manager.shutdown }.not_to raise_error
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
end
