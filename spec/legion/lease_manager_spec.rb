# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/lease_manager'
require 'legion/settings/resolver'

RSpec.describe Legion::Crypt::LeaseManager do
  subject(:manager) { described_class.instance }

  def lease_response(id:, username: 'rabbit_user', ttl: 3600, renewable: true, **)
    double('Vault::Secret', data: { username: username, password: "#{username}_pass" },
                           lease_id: id, lease_duration: ttl, renewable?: renewable)
  end

  let(:vault_response) { lease_response(id: 'original-id') }
  let(:lease_definitions) { { 'rabbitmq' => { 'path' => 'rabbitmq/creds/legion-role' } } }
  let(:vault_sys) { double('Vault sys', revoke: true) }
  let(:vault_logical) { double('Vault logical', read: vault_response) }
  let(:default_vault_client) { double('core Vault client', logical: vault_logical, sys: vault_sys) }

  before do
    manager.reset!
    hide_const('Legion::Transport::Connection') if defined?(Legion::Transport::Connection)
    hide_const('Legion::Data::Connection') if defined?(Legion::Data::Connection)
    hide_const('Legion::Cache') if defined?(Legion::Cache)
    allow(Legion::Crypt).to receive(:vault_client).and_return(default_vault_client)
  end

  after { manager.reset! }

  describe 'static acquisition and lookup' do
    it 'shares cached credentials between String and Symbol names without acquiring twice' do
      expect(vault_logical).to receive(:read).once.with(path: 'rabbitmq/creds/legion-role').and_return(vault_response)
      manager.start(lease_definitions)
      manager.start({ rabbitmq: { path: 'rabbitmq/creds/legion-role' } })

      expect(manager.fetch('rabbitmq', :username)).to eq('rabbit_user')
      expect(manager.fetch(:rabbitmq, 'username')).to eq('rabbit_user')
      expect(manager.lease_data('rabbitmq')).to eq(vault_response.data)
      expect(manager.lease_data(:rabbitmq)).to eq(vault_response.data)
      expect(manager.active_leases.keys).to eq([:rabbitmq])
      expect(manager.fetch(:missing, :username)).to be_nil
      expect(manager.fetch(:rabbitmq, :missing)).to be_nil
    end

    it 'uses the explicit Vault owner for acquisition and shutdown' do
      logical = double('cluster logical', read: vault_response)
      sys = double('cluster sys')
      client = double('cluster Vault client', logical: logical, sys: sys)
      expect(vault_logical).not_to receive(:read)
      expect(sys).to receive(:revoke).with(lease_id: 'original-id').once

      manager.start(lease_definitions, vault_client: client)
      expect(manager.fetch(:rabbitmq, :username)).to eq('rabbit_user')
      manager.shutdown
      expect(manager.lease_data(:rabbitmq)).to be_nil
    end

    it 'keeps a lease attached to the client that acquired it when the default client changes' do
      acquired_sys = double('acquiring sys')
      next_sys = double('replacement default sys')
      next_owner = double('replacement default Vault client', sys: next_sys)
      logical = double('acquiring logical')
      owner = double('acquiring Vault client', logical: logical, sys: acquired_sys)
      allow(Legion::Crypt).to receive(:vault_client).and_return(owner)
      allow(logical).to receive(:read) do
        allow(Legion::Crypt).to receive(:vault_client).and_return(next_owner)
        vault_response
      end
      expect(acquired_sys).to receive(:revoke).with(lease_id: 'original-id').once
      expect(next_sys).not_to receive(:revoke)

      manager.start(lease_definitions)
      expect(manager.fetch(:rabbitmq, :username)).to eq('rabbit_user')
      manager.shutdown
    end

    it 'permits settings fallback instead of serving expired credentials after reacquisition fails' do
      original = lease_response(id: 'expired-id', ttl: 1)
      allow(vault_logical).to receive(:read).and_return(original)
      manager.start(lease_definitions)
      connection = { password: 'fallback-password' }
      allow(Legion::Settings.loader).to receive(:settings).and_return(transport: { connection: connection })
      manager.register_ref(:rabbitmq, :password, %i[transport connection password])
      allow(Time).to receive(:now).and_return(Time.now + 2)
      allow(vault_logical).to receive(:read).and_raise(IOError, 'Vault unavailable')
      manager.start(lease_definitions)

      resolved = Legion::Settings::Resolver.resolve_value(['lease://rabbitmq#password', 'fallback-password'])
      expect(resolved).to eq('fallback-password')
      expect(manager.fetch(:rabbitmq, :password)).to be_nil
      expect(manager.lease_data(:rabbitmq)).to be_nil
      expect(manager.fetched_count).to eq(0)
      expect(manager.push_to_settings(:rabbitmq)).to eq(0)
      expect(connection[:password]).to eq('fallback-password')
      manager.shutdown
      expect(vault_sys).to have_received(:revoke).with(lease_id: 'expired-id').once
    end
  end

  describe 'pending initial acquisition' do
    let!(:clock) { { now: Time.now, monotonic: Process.clock_gettime(Process::CLOCK_MONOTONIC) } }

    before do
      allow(Time).to receive(:now) { clock[:now] }
      allow(Process).to receive(:clock_gettime).and_call_original
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { clock[:monotonic] }
    end

    it 'retries a failed initial read on a due maintenance pass and publishes registered references' do
      connection = { username: 'old' }
      allow(Legion::Settings.loader).to receive(:settings).and_return(transport: { connection: connection })
      attempts = 0
      allow(vault_logical).to receive(:read) do
        attempts += 1
        raise IOError, 'unavailable' if attempts == 1

        vault_response
      end
      manager.start(lease_definitions)
      manager.register_ref(:rabbitmq, :username, %i[transport connection username])
      expect(manager.fetch(:rabbitmq, :username)).to be_nil
      manager.send(:renew_approaching_leases)
      expect(attempts).to eq(1)

      clock[:now] += 1.01
      clock[:monotonic] += 1.01
      manager.send(:renew_approaching_leases)
      expect(attempts).to eq(2)
      expect(manager.fetch('rabbitmq', :username)).to eq('rabbit_user')
      expect(connection[:username]).to eq('rabbit_user')
    end

    it 'discards a pending retry superseded by an identity credential handoff' do
      allow(vault_logical).to receive(:read).and_raise(IOError, 'temporarily unavailable')
      manager.start({ blocker: { path: 'blocker' }, rabbitmq: { path: 'rabbitmq/creds/old-role' } })
      entered = Queue.new
      release = Queue.new
      allow(vault_logical).to receive(:read) do |path:|
        if path == 'blocker'
          entered << true
          release.pop
        end
        lease_response(id: "#{path}-id", username: 'old-role')
      end
      connection = { username: nil, password: nil }
      allow(Legion::Settings.loader).to receive(:settings).and_return(transport: { connection: connection })
      clock[:now] += 1.01
      clock[:monotonic] += 1.01
      worker = Thread.new { manager.send(:renew_approaching_leases) }
      Timeout.timeout(1) { entered.pop }

      identity = lease_response(id: 'identity-id', username: 'worker')
      manager.register_dynamic_lease(name: :rabbitmq, path: 'rabbitmq/creds/legionio-worker', response: identity,
                                     settings_refs: [{ key: :username, path: %i[transport connection username] },
                                                     { key: :password, path: %i[transport connection password] }])
      release << true
      Timeout.timeout(1) { worker.join }

      expect(manager.fetch(:rabbitmq, :username)).to eq('worker')
      expect(connection).to eq(identity.data)
      expect(vault_sys).not_to have_received(:revoke).with(lease_id: 'identity-id')
      manager.shutdown
      expect(vault_sys).to have_received(:revoke).with(lease_id: 'identity-id').once
    ensure
      worker&.kill
      worker&.join
    end

    it 'backs off through sixty seconds without duplicate retries or reads before each deadline' do
      attempts = 0
      allow(vault_logical).to receive(:read) do
        attempts += 1
        raise IOError, 'still unavailable'
      end
      manager.start(lease_definitions)
      manager.start({ rabbitmq: { path: 'rabbitmq/creds/legion-role' } })
      expect(attempts).to eq(1)

      [1, 2, 4, 8, 16, 32, 60, 60].each_with_index do |delay, index|
        clock[:now] += delay - 0.01
        clock[:monotonic] += delay - 0.01
        manager.send(:renew_approaching_leases)
        expect(attempts).to eq(index + 1)
        clock[:now] += 0.02
        clock[:monotonic] += 0.02
        manager.send(:renew_approaching_leases)
        manager.send(:renew_approaching_leases)
        expect(attempts).to eq(index + 2)
      end
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
      allow(vault_logical).to receive(:read).and_return(vault_response)
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

  describe '#update_settings_refs' do
    let(:settings) { { connections: [{ password: 'literal' }, { password: 'other' }] } }
    let(:password_path) { [:connections, 0, :password] }
    let(:binding) { { value: nil, source: 'opaque declaration' } }

    def install_settings_lease(name:, value:)
      manager.register_dynamic_lease(name: name, path: "credentials/#{name}",
                                     response: lease_response(id: nil, username: value, renewable: false), settings_refs: [])
    end

    def bind_setting(root:, name:, path:, record:, publish: nil)
      manager.update_settings_refs(settings: root, publish: publish) do |reader|
        target = path[0...-1].reduce(root) { |container, key| container[key] }
        { paths:       [path],
          assignments: [{ container: target, key: path.last, value: reader.call(name: name, key: :password) }],
          references:  [{ name: name, key: :password, path: path, binding: record }] }
      end
    end

    before do
      manager.start({}, vault_client: default_vault_client)
      install_settings_lease(name: :a, value: 'a')
      install_settings_lease(name: :b, value: 'b')
    end

    it 'replaces one destination without losing the old lease other destinations' do
      other_binding = { value: nil }
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      bind_setting(root: settings, name: :a, path: [:connections, 1, :password], record: other_binding)
      replacement_binding = { value: nil }
      bind_setting(root: settings, name: :b, path: password_path, record: replacement_binding)

      install_settings_lease(name: :a, value: 'rotated_a')
      expect(settings[:connections]).to eq([{ password: 'b_pass' }, { password: 'rotated_a_pass' }])
      expect(binding[:value]).to eq('a_pass')
      expect(other_binding[:value]).to eq('rotated_a_pass')
      install_settings_lease(name: :b, value: 'rotated_b')
      expect(settings[:connections][0][:password]).to eq('rotated_b_pass')
      expect(replacement_binding[:value]).to eq('rotated_b_pass')
    end

    it 'retires a binding without replacing it with another lease' do
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      manager.update_settings_refs(settings: settings) do
        { paths:       [password_path],
          assignments: [{ container: settings[:connections][0], key: :password, value: false }],
          references:  [] }
      end

      install_settings_lease(name: :a, value: 'rotated')
      expect(settings[:connections][0][:password]).to be(false)
      expect(binding[:value]).to eq('a_pass')
      expect(manager.push_to_settings(:a)).to eq(0)
    end

    it 'retains the original declaration and tracks values through repeated resolution and rotation' do
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      install_settings_lease(name: :a, value: 'rotated')
      expect(binding).to eq(value: 'rotated_pass', source: 'opaque declaration')

      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      expect(manager.push_to_settings(:a)).to eq(1)
      install_settings_lease(name: :a, value: 'final')
      expect(settings[:connections][0][:password]).to eq('final_pass')
      expect(binding[:value]).to eq('final_pass')
    end

    it 'tracks successful push values even after a caller overwrites the destination' do
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      settings[:connections][0][:password] = 'explicit edit'
      binding[:value] = 'previous observation'
      expect(manager.push_to_settings(:a)).to eq(1)
      expect(settings[:connections][0][:password]).to eq('a_pass')
      expect(binding[:value]).to eq('a_pass')
    end

    it 'keeps standalone destinations separate from the active loader' do
      active_settings = { connections: [{ password: 'active literal' }] }
      allow(Legion::Settings.loader).to receive(:settings).and_return(active_settings)
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      install_settings_lease(name: :a, value: 'rotated')

      expect(settings[:connections][0][:password]).to eq('rotated_pass')
      expect(active_settings[:connections][0][:password]).to eq('active literal')
    end

    it 'follows a published loader when its settings root is rebuilt' do
      active_settings = { connections: [{ password: 'old loader' }] }
      allow(Legion::Settings.loader).to receive(:settings) { active_settings }
      publication = ->(_proposal) { active_settings = settings }
      bind_setting(root: settings, name: :a, path: password_path, record: binding, publish: publication)
      active_settings = { connections: [{ password: 'rebuilt' }] }

      install_settings_lease(name: :a, value: 'rotated')
      expect(active_settings[:connections][0][:password]).to eq('rotated_pass')
      expect(settings[:connections][0][:password]).to eq('a_pass')
      expect(binding[:value]).to eq('rotated_pass')
    end

    it 'rejects ambiguous writers before applying any assignments' do
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      expect do
        manager.update_settings_refs(settings: settings) do
          { paths:       [password_path],
            assignments: [{ container: settings[:connections][0], key: :password, value: 'invalid' }],
            references:  [
              { name: :a, key: :password, path: password_path, binding: { value: nil } },
              { name: :b, key: :password, path: password_path, binding: { value: nil } }
            ] }
        end
      end.to raise_error(ArgumentError)

      expect(settings[:connections][0][:password]).to eq('a_pass')
      install_settings_lease(name: :a, value: 'rotated')
      expect(settings[:connections][0][:password]).to eq('rotated_pass')
    end

    it 'validates every assignment before changing values or registrations' do
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      settings[:connections][1].freeze
      expect do
        manager.update_settings_refs(settings: settings) do
          { paths: [password_path], references: [],
            assignments: [
              { container: settings[:connections][0], key: :password, value: 'invalid' },
              { container: settings[:connections][1], key: :password, value: 'unwritable' }
            ] }
        end
      end.to raise_error(ArgumentError)

      expect(settings[:connections][0][:password]).to eq('a_pass')
      install_settings_lease(name: :a, value: 'rotated')
      expect(settings[:connections][0][:password]).to eq('rotated_pass')
    end

    it 'preserves assignments and bindings when preparation fails' do
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      expect do
        manager.update_settings_refs(settings: settings) { raise IOError, 'preparation failed' }
      end.to raise_error(IOError)

      expect(settings[:connections][0][:password]).to eq('a_pass')
      install_settings_lease(name: :a, value: 'rotated')
      expect(settings[:connections][0][:password]).to eq('rotated_pass')
      expect(binding[:value]).to eq('rotated_pass')
    end

    it 'restores assignments, registrations, and tracked values when publication fails' do
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      settings[:connections][0][:password] = 'explicit edit'
      replacement_binding = { value: 'previous observation' }
      publication = lambda do |_proposal|
        expect(settings[:connections][0][:password]).to eq('b_pass')
        expect(replacement_binding[:value]).to eq('b_pass')
        raise IOError, 'publication failed'
      end
      expect do
        bind_setting(root: settings, name: :b, path: password_path, record: replacement_binding, publish: publication)
      end.to raise_error(IOError)

      expect(settings[:connections][0][:password]).to eq('explicit edit')
      expect(binding[:value]).to eq('a_pass')
      expect(replacement_binding[:value]).to eq('previous observation')
      install_settings_lease(name: :b, value: 'unused')
      expect(settings[:connections][0][:password]).to eq('explicit edit')
      install_settings_lease(name: :a, value: 'retained')
      expect(settings[:connections][0][:password]).to eq('retained_pass')
      expect(binding[:value]).to eq('retained_pass')
    end

    it 'restores the prior binding value separately from an explicitly changed destination on failed handoff' do
      install_settings_lease(name: :rabbitmq, value: 'original')
      bind_setting(root: settings, name: :rabbitmq, path: password_path, record: binding)
      settings[:connections][0][:password] = 'explicit edit'
      transport = double('RabbitMQ connection', force_reconnect: false, session_open?: false)
      stub_const('Legion::Transport::Connection', transport)

      expect(install_settings_lease(name: :rabbitmq, value: 'candidate')).to be(false)
      expect(settings[:connections][0][:password]).to eq('explicit edit')
      expect(binding[:value]).to eq('original_pass')
      expect(manager.fetch(:rabbitmq, :password)).to eq('original_pass')
    end

    it 'tracks and rolls back a candidate even when its value already matches the destination' do
      install_settings_lease(name: :rabbitmq, value: 'original')
      bind_setting(root: settings, name: :rabbitmq, path: password_path, record: binding)
      settings[:connections][0][:password] = 'candidate_pass'
      observed = []
      transport = double('RabbitMQ connection', session_open?: false)
      allow(transport).to receive(:force_reconnect) do
        observed << binding[:value]
        false
      end
      stub_const('Legion::Transport::Connection', transport)

      expect(install_settings_lease(name: :rabbitmq, value: 'candidate')).to be(false)
      expect(observed).to eq(%w[candidate_pass original_pass])
      expect(settings[:connections][0][:password]).to eq('candidate_pass')
      expect(binding[:value]).to eq('original_pass')
    end

    it 'rejects settings publication from a reconnect callback without deadlocking or retaining candidate values' do
      install_settings_lease(name: :rabbitmq, value: 'original')
      bind_setting(root: settings, name: :rabbitmq, path: password_path, record: binding)
      transport = double('RabbitMQ connection', session_open?: true)
      allow(transport).to receive(:force_reconnect) do
        bind_setting(root: settings, name: :rabbitmq, path: password_path, record: binding)
        true
      end
      stub_const('Legion::Transport::Connection', transport)

      result = Timeout.timeout(2) { install_settings_lease(name: :rabbitmq, value: 'candidate') }
      expect(result).to be(false)
      expect(settings[:connections][0][:password]).to eq('original_pass')
      expect(binding[:value]).to eq('original_pass')
    end

    it 'waits for an in-flight failed handoff before reading or publishing credentials' do
      install_settings_lease(name: :rabbitmq, value: 'original')
      bind_setting(root: settings, name: :rabbitmq, path: password_path, record: binding)
      reconnect_entered = Queue.new
      release_reconnect = Queue.new
      attempts = 0
      transport = double('RabbitMQ connection', session_open?: true)
      allow(transport).to receive(:force_reconnect) do
        attempts += 1
        if attempts == 1
          reconnect_entered << true
          release_reconnect.pop
          false
        else
          true
        end
      end
      stub_const('Legion::Transport::Connection', transport)
      installer = Thread.new { install_settings_lease(name: :rabbitmq, value: 'candidate') }
      updater = nil
      Timeout.timeout(2) do
        reconnect_entered.pop
        updater = Thread.new { bind_setting(root: settings, name: :rabbitmq, path: password_path, record: binding) }
        Thread.pass until updater.status == 'sleep'
        release_reconnect << true
        expect(installer.value).to be(false)
        updater.value
      end

      expect(settings[:connections][0][:password]).to eq('original_pass')
      expect(binding[:value]).to eq('original_pass')
    ensure
      release_reconnect << true if release_reconnect
      installer&.join(2)
      updater&.join(2)
    end

    it 'publishes all resolved destinations before a waiting rotation can observe the new bindings' do
      entered = Queue.new
      release = Queue.new
      published = nil
      updater = Thread.new do
        manager.update_settings_refs(settings: settings, publish: ->(_proposal) { published = settings[:connections].map(&:dup) }) do |reader|
          entered << true
          release.pop
          value = reader.call(name: :a, key: :password)
          { paths:       [password_path, [:connections, 1, :password]],
            assignments: settings[:connections].map { |target| { container: target, key: :password, value: value } },
            references:  [
              { name: :a, key: :password, path: password_path, binding: binding },
              { name: :a, key: :password, path: [:connections, 1, :password], binding: { value: nil } }
            ] }
        end
      end
      rotator = nil
      Timeout.timeout(2) do
        entered.pop
        rotator = Thread.new { install_settings_lease(name: :a, value: 'rotated') }
        Thread.pass until rotator.status == 'sleep'
        expect(settings[:connections]).to eq([{ password: 'literal' }, { password: 'other' }])
        release << true
        updater.value
        expect(rotator.value).to be(true)
      end

      expect(published).to eq([{ password: 'a_pass' }, { password: 'a_pass' }])
      expect(settings[:connections]).to eq([{ password: 'rotated_pass' }, { password: 'rotated_pass' }])
      expect(binding[:value]).to eq('rotated_pass')
    ensure
      release << true if release
      updater&.join(2)
      rotator&.join(2)
    end

    it 'wakes a waiting settings update when shutdown invalidates the lifecycle' do
      install_settings_lease(name: :rabbitmq, value: 'original')
      entered = Queue.new
      release = Queue.new
      transport = double('RabbitMQ connection', session_open?: true)
      allow(transport).to receive(:force_reconnect) do
        entered << true
        release.pop
        true
      end
      stub_const('Legion::Transport::Connection', transport)
      installer = Thread.new { install_settings_lease(name: :rabbitmq, value: 'candidate') }
      updater = nil
      Timeout.timeout(2) do
        entered.pop
        updater = Thread.new do
          bind_setting(root: settings, name: :rabbitmq, path: password_path, record: binding)
        rescue RuntimeError => e
          e
        end
        Thread.pass until updater.status == 'sleep'
        manager.request_stop
        expect(updater.value).to be_a(RuntimeError)
        release << true
        expect(installer.value).to be(false)
      end

      expect(settings[:connections][0][:password]).to eq('literal')
      expect(binding[:value]).to be_nil
    ensure
      release << true if release
      installer&.join(2)
      updater&.join(2)
    end

    it 'rejects publication after shutdown and clears previous binding records' do
      bind_setting(root: settings, name: :a, path: password_path, record: binding)
      manager.shutdown
      expect do
        bind_setting(root: settings, name: :a, path: password_path, record: binding)
      end.to raise_error(RuntimeError)

      manager.start({}, vault_client: default_vault_client)
      install_settings_lease(name: :a, value: 'restarted')
      expect(manager.push_to_settings(:a)).to eq(0)
      expect(settings[:connections][0][:password]).to eq('a_pass')
      expect(binding[:value]).to eq('a_pass')
    end
  end

  describe 'expiry-aware renewal worker' do
    it 'renews a short lease before expiry rather than waiting five seconds' do
      response = lease_response(id: 'short-id', ttl: 1)
      allow(vault_logical).to receive(:read).and_return(response)
      renewed = Queue.new
      allow(vault_sys).to receive(:renew) do |lease_id:|
        renewed << [lease_id, Process.clock_gettime(Process::CLOCK_MONOTONIC)]
        lease_response(id: lease_id)
      end
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      manager.start(lease_definitions)
      manager.start_renewal_thread

      id, renewed_at = Timeout.timeout(2) { renewed.pop }
      expect(id).to eq('short-id')
      expect(renewed_at - started).to be < 1
      manager.shutdown
      expect(manager.renewal_thread_alive?).to be(false)
    ensure
      manager.shutdown
    end

    it 'wakes a sleeping worker when a short dynamic lease is registered' do
      maintenance_finished = Queue.new
      allow(manager).to receive(:renew_approaching_leases).and_wrap_original do |original, *args, **kwargs|
        original.call(*args, **kwargs)
        maintenance_finished << Thread.current
      end
      renewed = Queue.new
      allow(vault_sys).to receive(:renew) do |lease_id:|
        renewed << [lease_id, Process.clock_gettime(Process::CLOCK_MONOTONIC)]
        lease_response(id: lease_id)
      end
      manager.start({})
      manager.start_renewal_thread
      worker = Timeout.timeout(1) { maintenance_finished.pop }
      Timeout.timeout(1) { Thread.pass until worker.status == 'sleep' }
      registered_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      manager.register_dynamic_lease(name: :short, path: 'short', response: lease_response(id: 'short-id', ttl: 1),
                                     settings_refs: [])

      id, renewed_at = Timeout.timeout(2) { renewed.pop }
      expect(id).to eq('short-id')
      expect(renewed_at - registered_at).to be < 1
    ensure
      manager.shutdown
    end
  end

  describe 'transactional credential handoff' do
    let(:connection) { { username: 'original', password: 'original_pass' } }
    let(:original_response) { lease_response(id: 'old-id', username: 'original') }
    let(:replacement) { lease_response(id: 'new-id', username: 'replacement') }
    let(:settings_refs) do
      [
        { key: :username, path: %i[transport connection username] },
        { key: :password, path: %i[transport connection password] }
      ]
    end
    let(:transport) { double('RabbitMQ connection', force_reconnect: true, session_open?: true) }

    before do
      allow(Legion::Settings.loader).to receive(:settings).and_return(transport: { connection: connection })
      stub_const('Legion::Transport::Connection', transport)
      manager.register_dynamic_lease(name: :rabbitmq, path: 'rabbitmq/creds/role',
                                     response: original_response, settings_refs: settings_refs)
      allow(vault_logical).to receive(:read).and_return(replacement)
    end

    it 'extends a renewed lease without interrupting consumers when credentials are unchanged' do
      renewed = double('renewed lease', data: {}, lease_id: 'old-id', lease_duration: 7200, renewable?: true)
      allow(vault_sys).to receive(:renew).and_return(renewed)
      original_expiry = manager.active_leases[:rabbitmq][:expires_at]
      expect(transport).not_to receive(:force_reconnect)

      manager.send(:renew_lease, :rabbitmq, manager.active_leases[:rabbitmq].dup)

      expect(manager.active_leases[:rabbitmq][:expires_at]).to be > original_expiry
      expect(manager.fetch(:rabbitmq, :username)).to eq('original')
      expect(connection).to eq(original_response.data)
    end

    it 'reconnects consumers when renewal actually rotates their credentials' do
      renewed = lease_response(id: 'old-id', username: 'rotated')
      allow(vault_sys).to receive(:renew).and_return(renewed)
      reconnected_with = []
      allow(transport).to receive(:force_reconnect) do
        reconnected_with << connection.dup
        true
      end

      manager.send(:renew_lease, :rabbitmq, manager.active_leases[:rabbitmq].dup)

      expect(reconnected_with).to eq([renewed.data])
      expect(manager.fetch(:rabbitmq, :username)).to eq('rotated')
    end

    it 'retires the old lease only after replacement settings and credentials reconnect successfully' do
      events = []
      allow(transport).to receive(:force_reconnect) do
        events << [:reconnect, connection.dup, manager.fetch(:rabbitmq, :username)]
        true
      end
      allow(vault_sys).to receive(:revoke) { |lease_id:| events << [:revoke, lease_id] }

      expect(manager.register_dynamic_lease(name: 'rabbitmq', path: 'rabbitmq/creds/role',
                                            response: replacement, settings_refs: settings_refs)).to be(true)
      expect(events).to eq([
                             [:reconnect, replacement.data, 'replacement'],
                             [:revoke, 'old-id']
                           ])
      manager.shutdown
      expect(events.last).to eq([:revoke, 'new-id'])
      expect(events.count { |event| event == [:revoke, 'old-id'] }).to eq(1)
    end

    it 'keeps every successful reissue owned until it has been replaced or shutdown' do
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      manager.reissue_lease('rabbitmq')
      expect(connection).to eq(replacement.data)
      expect(manager.fetch(:rabbitmq, :username)).to eq('replacement')
      expect(revoked).to eq(['old-id'])

      final_response = lease_response(id: 'final-id', username: 'final')
      allow(vault_logical).to receive(:read).and_return(final_response)
      manager.reissue_lease(:rabbitmq)
      expect(connection).to eq(final_response.data)
      expect(revoked).to eq(%w[old-id new-id])
      manager.shutdown
      expect(revoked).to eq(%w[old-id new-id final-id])
    end

    it 'preserves the old settings, cache and lease when replacement acquisition fails' do
      allow(vault_logical).to receive(:read).and_raise(IOError, 'unavailable')
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      manager.reissue_lease(:rabbitmq)

      expect(connection).to eq(original_response.data)
      expect(manager.lease_data(:rabbitmq)).to eq(original_response.data)
      expect(revoked).to be_empty
      manager.shutdown
      expect(revoked).to eq(['old-id'])
    end

    it 'rolls back failed RabbitMQ reconnect and retries cleanup of its candidate at shutdown' do
      allow(transport).to receive(:force_reconnect).and_return(false)
      cleanup_attempts = []
      cleanup_available = false
      allow(vault_sys).to receive(:revoke) do |lease_id:|
        cleanup_attempts << lease_id
        raise IOError, 'cleanup unavailable' unless cleanup_available
      end

      expect(manager.register_dynamic_lease(name: :rabbitmq, path: 'rabbitmq/creds/role',
                                            response: replacement, settings_refs: settings_refs)).to be(false)
      expect(connection).to eq(original_response.data)
      expect(manager.lease_data('rabbitmq')).to eq(original_response.data)
      expect(cleanup_attempts).not_to include('old-id')

      cleanup_available = true
      cleanup_attempts.clear
      manager.shutdown
      expect(cleanup_attempts).to contain_exactly('old-id', 'new-id')
    end

    it 'rejects a reported RabbitMQ reconnect when the session remains closed' do
      allow(transport).to receive(:session_open?).and_return(false)
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      manager.reissue_lease(:rabbitmq)

      expect(connection).to eq(original_response.data)
      expect(manager.fetch(:rabbitmq, :username)).to eq('original')
      expect(revoked).not_to include('old-id')
      manager.shutdown
      expect(revoked).to contain_exactly('old-id', 'new-id')
    end

    it 'rolls back reconnect exceptions without retiring the old lease' do
      allow(transport).to receive(:force_reconnect).and_raise(IOError, 'broker down')
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      manager.reissue_lease(:rabbitmq)

      expect(connection).to eq(original_response.data)
      expect(manager.lease_data(:rabbitmq)).to eq(original_response.data)
      expect(revoked).not_to include('old-id')
      manager.shutdown
      expect(revoked).to contain_exactly('old-id', 'new-id')
    end

    it 'rolls back a timed-out reconnect and retains both lease IDs for cleanup' do
      configuration = Legion::Crypt::Settings.default
      configuration[:vault][:operation_timeout] = 0.02
      allow(Legion::Settings).to receive(:[]).and_call_original
      allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
      allow(transport).to receive(:force_reconnect) { sleep(10) }
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      Timeout.timeout(1) { manager.reissue_lease(:rabbitmq) }

      expect(connection).to eq(original_response.data)
      expect(manager.lease_data(:rabbitmq)).to eq(original_response.data)
      expect(revoked).not_to include('old-id')
      manager.shutdown
      expect(revoked).to contain_exactly('old-id', 'new-id')
    end

    it 'restores all old destinations when candidate settings cannot be installed completely' do
      invalid_refs = [
        { key: :username, path: %i[transport connection username] },
        { key: :password, path: %i[transport missing password] }
      ]
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }

      expect(manager.register_dynamic_lease(name: :rabbitmq, path: 'rabbitmq/creds/role',
                                            response: replacement, settings_refs: invalid_refs)).to be(false)
      expect(connection).to eq(original_response.data)
      expect(manager.fetch(:rabbitmq, :username)).to eq('original')
      expect(revoked).not_to include('old-id')
      manager.shutdown
      expect(revoked).to contain_exactly('old-id', 'new-id')
    end

    it 'retries an unsuccessfully retired old lease on a later maintenance pass' do
      attempts = []
      available = false
      allow(vault_sys).to receive(:revoke) do |lease_id:|
        attempts << lease_id
        raise IOError, 'temporarily unavailable' unless available
      end
      manager.reissue_lease(:rabbitmq)
      expect(manager.fetch(:rabbitmq, :username)).to eq('replacement')
      expect(attempts).to eq(['old-id'])

      available = true
      future = Time.now + 61
      monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 61
      allow(Time).to receive(:now).and_return(future)
      allow(Process).to receive(:clock_gettime).and_call_original
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(monotonic)
      manager.send(:renew_approaching_leases)
      expect(attempts).to eq(%w[old-id old-id])
      manager.shutdown
      expect(attempts).to eq(%w[old-id old-id new-id])
    end

    it 'deduplicates an ID shared by current and failed retired ownership at shutdown' do
      cleanup_available = false
      revoked = []
      allow(vault_sys).to receive(:revoke) do |lease_id:|
        raise IOError, 'temporarily unavailable' unless cleanup_available

        revoked << lease_id
      end
      manager.reissue_lease(:rabbitmq)
      manager.register_dynamic_lease(name: :rabbitmq, path: 'rabbitmq/creds/role',
                                     response: original_response, settings_refs: settings_refs)
      cleanup_available = true
      manager.shutdown

      expect(revoked).to contain_exactly('old-id', 'new-id')
      expect(manager.fetch(:rabbitmq, :username)).to be_nil
    end
  end

  describe 'consumer handoff failures' do
    let(:connection) { { username: 'original' } }
    let(:original_response) { lease_response(id: 'old-id', username: 'original') }
    let(:replacement) { lease_response(id: 'new-id', username: 'replacement') }
    let(:refs) { [{ key: :username, path: %i[consumer username] }] }

    before do
      allow(Legion::Settings.loader).to receive(:settings).and_return(consumer: connection)
      allow(vault_logical).to receive(:read).and_return(replacement)
    end

    it 'preserves PostgreSQL credentials when reconnect_with_fresh_creds returns false' do
      consumer = double('PostgreSQL connection', reconnect_with_fresh_creds: true)
      stub_const('Legion::Data::Connection', consumer)
      manager.register_dynamic_lease(name: :postgresql, path: 'database/creds/role',
                                     response: original_response, settings_refs: refs)
      allow(consumer).to receive(:reconnect_with_fresh_creds).and_return(false)
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      manager.reissue_lease(:postgresql)

      expect(connection[:username]).to eq('original')
      expect(manager.fetch(:postgresql, :username)).to eq('original')
      expect(revoked).not_to include('old-id')
      manager.shutdown
      expect(revoked).to contain_exactly('old-id', 'new-id')
    end

    it 'does not treat an existing PostgreSQL connection test as proof of fresh credentials' do
      manager.register_dynamic_lease(name: :postgresql, path: 'database/creds/role',
                                     response: original_response, settings_refs: refs)
      database = double('existing database', disconnect: true, test_connection: true)
      stub_const('Legion::Data::Connection', double('legacy PostgreSQL connection', sequel: database))
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      manager.reissue_lease(:postgresql)

      expect(connection[:username]).to eq('original')
      expect(manager.fetch(:postgresql, :username)).to eq('original')
      expect(revoked).not_to include('old-id')
      manager.shutdown
      expect(revoked).to contain_exactly('old-id', 'new-id')
    end

    it 'preserves Redis credentials when restart returns false' do
      consumer = double('Redis cache', restart: true, connected?: true)
      stub_const('Legion::Cache', consumer)
      manager.register_dynamic_lease(name: :redis, path: 'redis/creds/role',
                                     response: original_response, settings_refs: refs)
      allow(consumer).to receive(:restart).and_return(false)
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      manager.reissue_lease(:redis)

      expect(connection[:username]).to eq('original')
      expect(manager.fetch(:redis, :username)).to eq('original')
      expect(revoked).not_to include('old-id')
      manager.shutdown
      expect(revoked).to contain_exactly('old-id', 'new-id')
    end

    it 'rejects Redis reconnect success when the cache is still disconnected' do
      consumer = double('Redis cache', reconnect: true, connected?: true)
      stub_const('Legion::Cache', consumer)
      manager.register_dynamic_lease(name: :redis, path: 'redis/creds/role',
                                     response: original_response, settings_refs: refs)
      allow(consumer).to receive(:connected?).and_return(false)
      revoked = []
      allow(vault_sys).to receive(:revoke) { |lease_id:| revoked << lease_id }
      manager.reissue_lease(:redis)

      expect(connection[:username]).to eq('original')
      expect(manager.fetch(:redis, :username)).to eq('original')
      expect(revoked).not_to include('old-id')
      manager.shutdown
      expect(revoked).to contain_exactly('old-id', 'new-id')
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
      allow(default_vault_client).to receive(:sys).and_return(sys)
    end

    after { manager.reset! }

    it 'continues acquisition after a stalled lease read times out' do
      allow(vault_logical).to receive(:read) do |path:|
        sleep(10) if path == 'slow'
        fresh_response
      end
      Timeout.timeout(1) { manager.start({ 'slow' => { path: 'slow' }, 'healthy' => { path: 'healthy' } }) }
      expect(manager.fetch('slow', :username)).to be_nil
      expect(manager.fetch('healthy', :username)).to eq('fresh')
    end

    it 'continues renewal after one lease times out' do
      manager.start({ 'slow' => { path: 'slow' } })
      allow(vault_logical).to receive(:read).and_return(fresh_response)
      manager.start({ 'healthy' => { path: 'healthy' } })
      manager.active_leases.each_value { |lease| lease[:expires_at] = Time.now + 0.1 }
      allow(sys).to receive(:renew) do |lease_id:|
        sleep(10) if lease_id == vault_response.lease_id
        fresh_response
      end

      Timeout.timeout(1) { manager.send(:renew_approaching_leases) }
      expect(manager.active_leases[:healthy][:expires_at]).to be > Time.now
      expect(manager.fetch('healthy', :username)).to eq('fresh')
    end

    it 'reacquires credentials after a timed-out renewal outlives the lease' do
      original = lease_response(id: 'short-id', ttl: 2)
      allow(vault_logical).to receive(:read).and_return(original)
      manager.start(lease_definitions)
      manager.register_ref(:rabbitmq, :username, %i[transport connection username])
      current_time = Time.now
      allow(Time).to receive(:now).and_return(current_time + 1.1)
      allow(sys).to receive(:renew) { sleep(10) }
      Timeout.timeout(1) { manager.send(:renew_approaching_leases) }
      expect(manager.fetch(:rabbitmq, :username)).to eq('rabbit_user')

      monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
      allow(Time).to receive(:now).and_return(current_time + 3)
      allow(Process).to receive(:clock_gettime).and_call_original
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(monotonic)
      allow(vault_logical).to receive(:read).and_return(fresh_response)
      manager.send(:renew_approaching_leases)

      expect(manager.fetch(:rabbitmq, :username)).to eq('fresh')
      expect(connection[:username]).to eq('fresh')
      expect(sys).to have_received(:revoke).with(lease_id: 'short-id').once
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
      snapshot = manager.active_leases[:rabbitmq].dup
      worker = Thread.new { manager.send(:renew_lease, :rabbitmq, snapshot) }
      Timeout.timeout(1) { entered.pop }
      manager.shutdown
      allow(vault_logical).to receive(:read).and_return(fresh_response)
      manager.start(lease_definitions)
      manager.register_ref('rabbitmq', :username, %i[transport connection username])
      manager.push_to_settings('rabbitmq')
      release << true
      Timeout.timeout(1) { worker.join }

      expect(manager.fetch('rabbitmq', :username)).to eq('fresh')
      expect(connection[:username]).to eq('fresh')
      expect(sys).to have_received(:revoke).with(lease_id: vault_response.lease_id).once
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
      allow(vault_logical).to receive(:read) do
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
      manager.shutdown
      expect(sys).to have_received(:revoke).with(lease_id: 'fresh-id').once
      expect(sys).to have_received(:revoke).with(lease_id: vault_response.lease_id).once
    ensure
      worker&.kill
      worker&.join
    end

    it 'detaches state and continues revocation after a stalled lease' do
      manager.start({ 'slow' => { path: 'slow' } })
      allow(vault_logical).to receive(:read).and_return(fresh_response)
      manager.start({ 'healthy' => { path: 'healthy' } })
      revoked = []
      allow(sys).to receive(:revoke) do |lease_id:|
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
