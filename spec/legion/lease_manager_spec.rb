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
           renewable:      true)
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
             renewable:      true)
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

  describe '#shutdown' do
    before { manager.start(lease_definitions) }

    it 'revokes active leases via Vault' do
      sys_double = instance_double(Vault::Sys)
      allow(Vault).to receive(:sys).and_return(sys_double)
      expect(sys_double).to receive(:revoke).with('rabbitmq/creds/legion-role/abc123')
      manager.shutdown
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
                                  renewable:      false)
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
                                    renewable:      false)
      manager.reset!
      allow(Vault).to receive_message_chain(:logical, :read).and_return(empty_lease_response)
      manager.start(lease_definitions)
      expect(Vault).not_to receive(:sys)
      manager.shutdown
    end
  end
end
