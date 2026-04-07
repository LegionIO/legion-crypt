# frozen_string_literal: true

require 'spec_helper'

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
  let(:sys_double)     { instance_double(Vault::Sys) }

  before do
    # Stub public Vault delegators on LeaseManager (vault_logical, vault_sys)
    allow(Legion::Crypt::LeaseManager.instance).to receive(:vault_logical).and_return(logical_double)
    allow(Legion::Crypt::LeaseManager.instance).to receive(:vault_sys).and_return(sys_double)
    allow(logical_double).to receive(:read).and_return(vault_response)
    allow(sys_double).to receive(:revoke)
    # Reset instance-level state between examples
    Legion::Crypt.instance_variable_set(:@bootstrap_lease_id, nil)
    Legion::Crypt.instance_variable_set(:@bootstrap_lease_expires, nil)
    Legion::Crypt::LeaseManager.instance.reset!
  end

  describe 'RMQ_ROLE_MAP' do
    it 'maps :agent to legionio-infra' do
      expect(described_class::RMQ_ROLE_MAP[:agent]).to eq('legionio-infra')
    end

    it 'maps :worker to legionio-worker' do
      expect(described_class::RMQ_ROLE_MAP[:worker]).to eq('legionio-worker')
    end

    it 'maps :infra to legionio-infra' do
      expect(described_class::RMQ_ROLE_MAP[:infra]).to eq('legionio-infra')
    end

    it 'is frozen' do
      expect(described_class::RMQ_ROLE_MAP).to be_frozen
    end
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
      allow(described_class).to receive(:vault_connected?).and_return(true)
      Legion::Settings.loader.settings[:transport] ||= {}
      Legion::Settings.loader.settings[:transport][:connection] ||= {}
    end

    after do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
    end

    it 'reads from the bootstrap path' do
      expect(logical_double).to receive(:read).with('rabbitmq/creds/legionio-bootstrap').and_return(vault_response)
      described_class.fetch_bootstrap_rmq_creds
    end

    it 'stores the bootstrap lease_id' do
      described_class.fetch_bootstrap_rmq_creds
      expect(described_class.instance_variable_get(:@bootstrap_lease_id))
        .to eq('rabbitmq/creds/legionio-bootstrap/abc123')
    end

    it 'stores a bootstrap_lease_expires time capped at 300 seconds' do
      before_call = Time.now
      described_class.fetch_bootstrap_rmq_creds
      expires = described_class.instance_variable_get(:@bootstrap_lease_expires)
      expect(expires).to be_a(Time)
      expect(expires).to be >= before_call
      expect(expires).to be <= (before_call + 300 + 1)
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

      it 'stores the bootstrap lease_id from string-keyed response' do
        described_class.fetch_bootstrap_rmq_creds
        expect(described_class.instance_variable_get(:@bootstrap_lease_id))
          .to eq('rabbitmq/creds/legionio-bootstrap/str123')
      end
    end

    context 'when vault is not connected' do
      before { allow(described_class).to receive(:vault_connected?).and_return(false) }

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

    context 'when Vault returns nil' do
      before { allow(logical_double).to receive(:read).and_return(nil) }

      it 'returns nil without raising' do
        expect { described_class.fetch_bootstrap_rmq_creds }.not_to raise_error
        expect(described_class.instance_variable_get(:@bootstrap_lease_id)).to be_nil
      end
    end

    context 'when Vault returns a response with no data' do
      let(:no_data_response) do
        double('Vault::Secret', data: nil, lease_id: 'lease/abc', lease_duration: 300, renewable?: false)
      end

      before { allow(logical_double).to receive(:read).and_return(no_data_response) }

      it 'returns nil without raising' do
        expect { described_class.fetch_bootstrap_rmq_creds }.not_to raise_error
      end
    end

    context 'when Vault raises an error' do
      before { allow(logical_double).to receive(:read).and_raise(StandardError, 'vault unavailable') }

      it 'does not raise and logs a warning' do
        expect { described_class.fetch_bootstrap_rmq_creds }.not_to raise_error
      end

      it 'does not store a lease_id on error' do
        described_class.fetch_bootstrap_rmq_creds
        expect(described_class.instance_variable_get(:@bootstrap_lease_id)).to be_nil
      end
    end
  end

  describe '.swap_to_identity_creds' do
    let(:transport_connection_double) do
      double('Legion::Transport::Connection', session_open?: true)
    end

    before do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = true
      allow(described_class).to receive(:vault_connected?).and_return(true)
      allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra').and_return(identity_response)
      allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-worker').and_return(identity_response)
      allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-custom').and_return(identity_response)
      Legion::Settings.loader.settings[:transport] ||= {}
      Legion::Settings.loader.settings[:transport][:connection] ||= {}
    end

    after do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
    end

    it 'returns early when vault is not connected' do
      allow(described_class).to receive(:vault_connected?).and_return(false)
      expect(logical_double).not_to receive(:read)
      described_class.swap_to_identity_creds(mode: :agent)
    end

    it 'returns early when dynamic_rmq_creds? is false' do
      Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
      expect(logical_double).not_to receive(:read)
      described_class.swap_to_identity_creds(mode: :agent)
    end

    it 'returns early for :lite mode' do
      expect(logical_double).not_to receive(:read)
      described_class.swap_to_identity_creds(mode: :lite)
    end

    context 'role selection from RMQ_ROLE_MAP' do
      before do
        stub_const('Legion::Transport::Connection', transport_connection_double)
        allow(transport_connection_double).to receive(:force_reconnect)
        allow(Legion::Crypt::LeaseManager.instance).to receive(:register_dynamic_lease)
      end

      it 'uses legionio-infra for :agent mode' do
        expect(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra').and_return(identity_response)
        described_class.swap_to_identity_creds(mode: :agent)
      end

      it 'uses legionio-infra for :infra mode' do
        expect(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra').and_return(identity_response)
        described_class.swap_to_identity_creds(mode: :infra)
      end

      it 'uses legionio-worker for :worker mode' do
        expect(logical_double).to receive(:read).with('rabbitmq/creds/legionio-worker').and_return(identity_response)
        described_class.swap_to_identity_creds(mode: :worker)
      end

      it 'uses a fallback role name for unknown modes' do
        expect(logical_double).to receive(:read).with('rabbitmq/creds/legionio-custom').and_return(identity_response)
        described_class.swap_to_identity_creds(mode: :custom)
      end
    end

    context 'when Vault returns identity creds' do
      before do
        stub_const('Legion::Transport::Connection', transport_connection_double)
        allow(transport_connection_double).to receive(:force_reconnect)
        allow(Legion::Crypt::LeaseManager.instance).to receive(:register_dynamic_lease)
      end

      it 'registers the lease with LeaseManager' do
        expect(Legion::Crypt::LeaseManager.instance).to receive(:register_dynamic_lease).with(
          name:          :rabbitmq,
          path:          'rabbitmq/creds/legionio-infra',
          response:      identity_response,
          settings_refs: [
            { path: %i[transport connection user],     key: :username },
            { path: %i[transport connection password], key: :password }
          ]
        )
        described_class.swap_to_identity_creds(mode: :agent)
      end

      it 'writes identity username to transport connection settings' do
        described_class.swap_to_identity_creds(mode: :agent)
        conn = Legion::Settings.loader.settings.dig(:transport, :connection)
        expect(conn[:user]).to eq('identity_user')
      end

      it 'writes identity password to transport connection settings' do
        described_class.swap_to_identity_creds(mode: :agent)
        conn = Legion::Settings.loader.settings.dig(:transport, :connection)
        expect(conn[:password]).to eq('identity_pass')
      end

      it 'calls force_reconnect on Transport::Connection' do
        expect(transport_connection_double).to receive(:force_reconnect)
        described_class.swap_to_identity_creds(mode: :agent)
      end

      it 'revokes the bootstrap lease after successful reconnect' do
        described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/xyz789')
        expect(sys_double).to receive(:revoke).with('boot/lease/xyz789')
        described_class.swap_to_identity_creds(mode: :agent)
      end
    end

    context 'when Vault returns string-keyed identity data' do
      before do
        stub_const('Legion::Transport::Connection', transport_connection_double)
        allow(transport_connection_double).to receive(:force_reconnect)
        allow(Legion::Crypt::LeaseManager.instance).to receive(:register_dynamic_lease)
        allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra')
                                               .and_return(identity_response_string_keys)
      end

      it 'writes identity username to transport connection settings from string key' do
        described_class.swap_to_identity_creds(mode: :agent)
        conn = Legion::Settings.loader.settings.dig(:transport, :connection)
        expect(conn[:user]).to eq('identity_user_str')
      end

      it 'writes identity password to transport connection settings from string key' do
        described_class.swap_to_identity_creds(mode: :agent)
        conn = Legion::Settings.loader.settings.dig(:transport, :connection)
        expect(conn[:password]).to eq('identity_pass_str')
      end
    end

    context 'when Vault returns no data for identity creds' do
      before { allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra').and_return(nil) }

      it 'raises an error' do
        expect { described_class.swap_to_identity_creds(mode: :agent) }.to raise_error(RuntimeError, /Failed to fetch/)
      end
    end

    context 'when Transport::Connection is not defined' do
      before { allow(Legion::Crypt::LeaseManager.instance).to receive(:register_dynamic_lease) }

      it 'does not raise when Transport module is absent' do
        hide_const('Legion::Transport::Connection')
        expect { described_class.swap_to_identity_creds(mode: :agent) }.not_to raise_error
      end
    end

    context 'when transport reconnect fails (session not open)' do
      let(:closed_connection) { double('Legion::Transport::Connection', session_open?: false) }

      before do
        stub_const('Legion::Transport::Connection', closed_connection)
        allow(closed_connection).to receive(:force_reconnect)
        allow(Legion::Crypt::LeaseManager.instance).to receive(:register_dynamic_lease)
      end

      it 'raises an error and does not revoke the bootstrap lease' do
        described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/xyz789')
        expect(sys_double).not_to receive(:revoke)
        expect { described_class.swap_to_identity_creds(mode: :agent) }.to raise_error(RuntimeError, /reconnect failed/)
      end
    end
  end

  describe '.revoke_bootstrap_lease' do
    it 'is a no-op when no bootstrap lease is stored' do
      described_class.instance_variable_set(:@bootstrap_lease_id, nil)
      expect(sys_double).not_to receive(:revoke)
      expect { described_class.revoke_bootstrap_lease }.not_to raise_error
    end

    it 'revokes the stored bootstrap lease' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      expect(sys_double).to receive(:revoke).with('boot/lease/abc123')
      described_class.revoke_bootstrap_lease
    end

    it 'clears @bootstrap_lease_id after revocation' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      described_class.revoke_bootstrap_lease
      expect(described_class.instance_variable_get(:@bootstrap_lease_id)).to be_nil
    end

    it 'clears @bootstrap_lease_expires after revocation' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      described_class.instance_variable_set(:@bootstrap_lease_expires, Time.now + 100)
      described_class.revoke_bootstrap_lease
      expect(described_class.instance_variable_get(:@bootstrap_lease_expires)).to be_nil
    end

    it 'does not raise when Vault revocation fails' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      allow(sys_double).to receive(:revoke).and_raise(StandardError, 'vault down')
      expect { described_class.revoke_bootstrap_lease }.not_to raise_error
    end

    it 'clears @bootstrap_lease_id even when revocation fails' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      allow(sys_double).to receive(:revoke).and_raise(StandardError, 'vault down')
      described_class.revoke_bootstrap_lease
      expect(described_class.instance_variable_get(:@bootstrap_lease_id)).to be_nil
    end

    it 'clears @bootstrap_lease_expires even when revocation fails' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      described_class.instance_variable_set(:@bootstrap_lease_expires, Time.now + 100)
      allow(sys_double).to receive(:revoke).and_raise(StandardError, 'vault down')
      described_class.revoke_bootstrap_lease
      expect(described_class.instance_variable_get(:@bootstrap_lease_expires)).to be_nil
    end

    it 'is idempotent — second call is a no-op' do
      described_class.instance_variable_set(:@bootstrap_lease_id, 'boot/lease/abc123')
      described_class.revoke_bootstrap_lease
      expect(sys_double).not_to receive(:revoke)
      described_class.revoke_bootstrap_lease
    end
  end

  describe 'start_lease_manager with dynamic_rmq_creds guard' do
    before do
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start_renewal_thread)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:shutdown)
    end

    context 'when dynamic_rmq_creds is true and no static leases' do
      before do
        Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = true
        Legion::Settings[:crypt][:vault][:connected] = true
        Legion::Settings[:crypt][:vault][:leases] = {}
      end

      after do
        Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
        Legion::Settings[:crypt][:vault][:connected] = false
      end

      it 'starts the renewal thread even without static leases' do
        Legion::Crypt.send(:start_lease_manager)
        expect(Legion::Crypt::LeaseManager.instance).to have_received(:start_renewal_thread)
      end
    end

    context 'when dynamic_rmq_creds is false and no static leases' do
      before do
        Legion::Settings[:crypt][:vault][:dynamic_rmq_creds] = false
        Legion::Settings[:crypt][:vault][:connected] = true
        Legion::Settings[:crypt][:vault][:leases] = {}
      end

      after do
        Legion::Settings[:crypt][:vault][:connected] = false
      end

      it 'does not start the renewal thread without static leases' do
        Legion::Crypt.send(:start_lease_manager)
        expect(Legion::Crypt::LeaseManager.instance).not_to have_received(:start_renewal_thread)
      end
    end
  end
end
