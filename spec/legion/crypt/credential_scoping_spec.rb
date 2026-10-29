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
  let(:vault_client) { double('Vault::Client', logical: logical_double, sys: sys_double) }
  let(:manager) { Legion::Crypt::LeaseManager.instance }

  before do
    allow(Vault).to receive(:client).and_return(vault_client)
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
      allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra').and_return(identity_response)
      allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-worker').and_return(identity_response)
      allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-custom').and_return(identity_response)
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
        expect(logical_double).to receive(:read).with("rabbitmq/creds/#{role}").and_return(identity_response)
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
      allow(sys_double).to receive(:revoke).with(bootstrap_lease_id) { events << :revoke_bootstrap }

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
      allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra').and_return(identity_response_string_keys)

      described_class.swap_to_identity_creds(mode: :agent)

      expect(connection_settings).to include(user: 'identity_user_str', password: 'identity_pass_str')
      expect(manager.fetch('rabbitmq', 'username')).to eq('identity_user_str')
      expect(sys_double).to have_received(:revoke).with(bootstrap_lease_id)
    end

    it 'retains bootstrap and existing settings when acquisition returns no response' do
      allow(logical_double).to receive(:read).with('rabbitmq/creds/legionio-infra').and_return(nil)

      expect { described_class.swap_to_identity_creds(mode: :agent) }.to raise_error(RuntimeError)

      expect(connection_settings).to include(user: 'bootstrap_user', password: 'bootstrap_pass')
      expect(sys_double).not_to have_received(:revoke).with(bootstrap_lease_id)
      described_class.revoke_bootstrap_lease
      expect(sys_double).to have_received(:revoke).with(bootstrap_lease_id)
    end

    it 'installs credentials without requiring a reconnect when the transport consumer is absent' do
      hide_const('Legion::Transport::Connection')

      described_class.swap_to_identity_creds(mode: :agent)

      expect(connection_settings).to include(user: 'identity_user', password: 'identity_pass')
      expect(manager.fetch(:rabbitmq, :username)).to eq('identity_user')
      expect(sys_double).to have_received(:revoke).with(bootstrap_lease_id)
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
          expect(sys_double).not_to have_received(:revoke).with(vault_response.lease_id)
          expect(sys_double).not_to have_received(:revoke).with(bootstrap_lease_id)
          described_class.revoke_bootstrap_lease
          expect(sys_double).to have_received(:revoke).with(bootstrap_lease_id)
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
            expect(sys_double).to have_received(:revoke).with(identity_response.lease_id).at_least(:once)
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
      expect(sys_double).to receive(:revoke).with('boot/lease/abc123')
      described_class.revoke_bootstrap_lease
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
