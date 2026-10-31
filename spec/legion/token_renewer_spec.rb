# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/token_renewer'

RSpec.describe Legion::Crypt::TokenRenewer do
  let(:cluster_name) { :primary }
  let(:config) do
    {
      token: 'hvs.initial-token', lease_duration: 100, renewable: true,
      connected: true, auth_method: 'kerberos', address: 'vault.example.com',
      kerberos: { service_principal: 'HTTP/vault.example.com', auth_path: 'auth/kerberos/login' }
    }
  end
  let(:vault_client) { Legion::Crypt::VaultClient.new(address: 'https://vault.example.com', token: 'hvs.initial-token') }
  let(:auth_token) { double('AuthToken') }
  let(:renew_result) do
    double('RenewResult', auth: double('Auth', lease_duration: 200, client_token: 'hvs.renewed', renewable?: false))
  end

  let(:renewer) { described_class.new(cluster_name: cluster_name, config: config, vault_client: vault_client) }
  let(:lease_manager) { instance_double(Legion::Crypt::LeaseManager, reissue_all: nil) }
  let(:background_threads) { [] }

  before do
    allow(vault_client).to receive(:auth_token).and_return(auth_token)
    allow(auth_token).to receive(:revoke_self)
    allow(Legion::Crypt::LeaseManager).to receive(:instance).and_return(lease_manager)
    allow(Legion::Crypt).to receive(:stopping).and_return(false)
  end

  after do
    renewer.request_stop
    background_threads.each do |thread|
      thread.kill if thread.alive?
      thread.join(1)
    end
    renewer.stop(deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1)
  end

  def run_in_background(**, &)
    Thread.new(&).tap { |thread| background_threads << thread }
  end

  def await_event(queue:, **)
    Timeout.timeout(1) { queue.pop }
  end

  def finish_thread(thread:, **)
    raise 'background operation did not finish' unless thread.join(1)

    thread.value
  end

  describe '#renew_token' do
    it 'returns false when renewal fails' do
      allow(auth_token).to receive(:renew_self).and_raise(StandardError, 'token expired')
      result = renewer.renew_token
      expect(result).to be false
    end
  end

  describe '#reauth_kerberos' do
    it 'returns false when re-auth fails' do
      allow(Legion::Crypt::KerberosAuth).to receive(:login)
        .and_raise(Legion::Crypt::KerberosAuth::AuthError, 'no TGT')
      result = renewer.reauth_kerberos
      expect(result).to be false
    end
  end

  describe '#start and #stop' do
    it 'starts and stops the renewal thread' do
      allow(auth_token).to receive(:renew_self).and_return(renew_result)
      allow(vault_client).to receive(:token).and_return('hvs.initial-token')
      allow(auth_token).to receive(:revoke_self)
      renewer.start
      expect(renewer.running?).to be true
      renewer.stop
      expect(renewer.running?).to be false
    end
  end

  describe '#revoke_token (private)' do
    context 'when auth_method is kerberos' do
      it 'calls revoke_self on auth_token' do
        allow(vault_client).to receive(:token).and_return('hvs.initial-token')
        expect(auth_token).to receive(:revoke_self)
        renewer.send(:revoke_token)
      end
    end

    context 'when auth_method is not kerberos' do
      let(:config) do
        {
          token: 'hvs.env-token', lease_duration: 100, renewable: true,
          connected: true, auth_method: 'token', address: 'vault.example.com'
        }
      end

      it 'does not revoke the token' do
        allow(vault_client).to receive(:token).and_return('hvs.env-token')
        expect(auth_token).not_to receive(:revoke_self)
        renewer.send(:revoke_token)
      end
    end

    context 'when auth_method is nil' do
      let(:config) do
        {
          token: 'hvs.env-token', lease_duration: 100, renewable: true,
          connected: true, address: 'vault.example.com'
        }
      end

      it 'does not revoke the token' do
        allow(vault_client).to receive(:token).and_return('hvs.env-token')
        expect(auth_token).not_to receive(:revoke_self)
        renewer.send(:revoke_token)
      end
    end

    context 'when vault_client has no token' do
      it 'does not attempt revocation' do
        allow(vault_client).to receive(:token).and_return(nil)
        expect(auth_token).not_to receive(:revoke_self)
        renewer.send(:revoke_token)
      end
    end

    context 'when revoke_self raises' do
      it 'leaves the worker stopped and permits a subsequent restart' do
        allow(auth_token).to receive(:revoke_self).and_raise(StandardError, 'network error')
        renewer.start

        renewer.stop

        expect(renewer.running?).to be false
        renewer.start
        expect(renewer.running?).to be true
      end
    end
  end

  describe '#next_backoff' do
    it 'doubles up to the cap' do
      expect(renewer.next_backoff).to eq(30)
      expect(renewer.next_backoff).to eq(60)
      expect(renewer.next_backoff).to eq(120)
      expect(renewer.next_backoff).to eq(240)
      expect(renewer.next_backoff).to eq(480)
      expect(renewer.next_backoff).to eq(600)
      expect(renewer.next_backoff).to eq(600)
    end
  end

  describe '#reset_backoff' do
    it 'resets the backoff to initial value' do
      renewer.next_backoff
      renewer.next_backoff
      renewer.reset_backoff
      expect(renewer.next_backoff).to eq(30)
    end
  end

  describe 'LDAP token lifetime' do
    let(:config) do
      { token: 'ldap-token', lease_duration: 0.12, expires_at: Time.now + 0.12,
        renewable: true, connected: true, auth_method: 'ldap' }
    end

    before { expect(Legion::Crypt::KerberosAuth).not_to receive(:login) }

    it 'retries transient failures inside the remaining lifetime without disconnecting a usable token' do
      attempts = 0
      failed = Queue.new
      recovered = Queue.new
      original_expiry = config[:expires_at]
      allow(auth_token).to receive(:renew_self) do
        attempts += 1
        if attempts == 1
          failed << true
          raise IOError, 'temporary connection failure'
        end
        recovered << true
        renew_result
      end
      renewer.start
      await_event(queue: failed)
      expect(config[:connected]).to be(true)
      await_event(queue: recovered)
      Timeout.timeout(1) { sleep(0.001) until config[:expires_at] > original_expiry }
      expect(config[:connected]).to be(true)
      expect(config[:relogin_required]).to be(false)
      expect(attempts).to eq(2)
    end

    it 'bounds a blocked renewal by expiry and ends in the login-required state' do
      entered = Queue.new
      blocked = Queue.new
      allow(auth_token).to receive(:renew_self) do
        entered << Thread.current
        blocked.pop
      end
      renewer.start
      worker = await_event(queue: entered)
      finish_thread(thread: worker)
      expect(config[:connected]).to be(false)
      expect(config[:relogin_required]).to be(true)
      expect(renewer.running?).to be(false)
    end

    it 'stops retrying when persistent transient failures exhaust the token lifetime' do
      attempts = Queue.new
      allow(auth_token).to receive(:renew_self) do
        attempts << Thread.current
        raise IOError, 'Vault unavailable'
      end
      renewer.start
      worker = await_event(queue: attempts)
      finish_thread(thread: worker)
      expect(attempts.size).to be_between(1, 7)
      expect(config[:connected]).to be(false)
      expect(config[:relogin_required]).to be(true)
    end
  end

  describe 'shutdown races' do
    let(:entered) { Queue.new }
    let(:release) { Queue.new }
    let(:reauth_result) do
      { token: 'hvs.late-token', lease_duration: 300, renewable: false, policies: [], metadata: {} }
    end

    it 'rejects a renewal completing after the nonblocking stop request' do
      original_config = config.dup
      allow(auth_token).to receive(:renew_self) do
        entered << true
        release.pop
        renew_result
      end
      operation = run_in_background { renewer.renew_token }
      await_event(queue: entered)

      finish_thread(thread: run_in_background { renewer.request_stop })
      expect(operation).to be_alive
      release << true

      expect(finish_thread(thread: operation)).to be false
      expect(config).to eq(original_config)
      expect(vault_client.token).to eq('hvs.initial-token')
      expect(lease_manager).not_to have_received(:reissue_all)
    end

    it 'rejects stale reauthentication after stop and a new generation has started' do
      original_config = config.dup
      allow(Legion::Crypt::KerberosAuth).to receive(:login) do
        entered << true
        release.pop
        reauth_result
      end
      operation = run_in_background { renewer.reauth_kerberos }
      await_event(queue: entered)

      finish_thread(thread: run_in_background { renewer.stop })
      renewer.start
      release << true

      expect(finish_thread(thread: operation)).to be false
      expect(config).to eq(original_config)
      expect(vault_client.token).to eq('hvs.initial-token')
      expect(lease_manager).not_to have_received(:reissue_all)

      allow(auth_token).to receive(:renew_self).and_return(renew_result)
      expect(renewer.renew_token).to be true
      expect(config[:lease_duration]).to eq(200)
    end

    it 'keeps an in-flight lease reissue cancelled after a token worker restart' do
      allow(Legion::Crypt::KerberosAuth).to receive(:login).and_return(reauth_result)
      allow(lease_manager).to receive(:reissue_all) do |active:|
        entered << active
        release.pop
      end
      operation = run_in_background { renewer.reauth_kerberos }
      active = await_event(queue: entered)
      published = []
      expect(active.call).to be true
      expect(active.call { published << :current }).to be true

      finish_thread(thread: run_in_background { renewer.request_stop })
      renewer.start

      expect(active.call).to be false
      expect(active.call { published << :stale }).to be false
      expect(published).to eq([:current])
      release << true
      expect(finish_thread(thread: operation)).to be true
      expect(vault_client.token).to eq('hvs.late-token')
    end

    it 'rejects completed reauthentication while global shutdown is in progress' do
      original_config = config.dup
      allow(Legion::Crypt::KerberosAuth).to receive(:login) do
        entered << true
        release.pop
        reauth_result
      end
      operation = run_in_background { renewer.reauth_kerberos }
      await_event(queue: entered)

      allow(Legion::Crypt).to receive(:stopping).and_return(true)
      release << true

      expect(finish_thread(thread: operation)).to be false
      expect(config).to eq(original_config)
      expect(vault_client.token).to eq('hvs.initial-token')
      expect(lease_manager).not_to have_received(:reissue_all)
    end

    it 'does not reauthenticate or mark disconnected after a stopped worker fails' do
      allow(renewer).to receive(:sleep_duration).and_return(0)
      allow(auth_token).to receive(:renew_self) do
        entered << true
        release.pop
        raise StandardError, 'renewal failed after stop'
      end
      allow(Legion::Crypt::KerberosAuth).to receive(:login)
      renewer.start
      worker = renewer.instance_variable_get(:@thread)
      await_event(queue: entered)

      renewer.request_stop
      release << true
      finish_thread(thread: worker)

      expect(config[:connected]).to be true
      expect(Legion::Crypt::KerberosAuth).not_to have_received(:login)
      expect(lease_manager).not_to have_received(:reissue_all)

      allow(renewer).to receive(:sleep_duration).and_return(3600)
      renewer.start
      expect(renewer.next_backoff).to eq(described_class::INITIAL_BACKOFF)
    end

    it 'bounds a blocked worker join without revoking or spawning replacement workers' do
      config[:renewable] = false
      original_config = config.dup
      allow(renewer).to receive(:sleep_duration).and_return(0)
      allow(Legion::Crypt::KerberosAuth).to receive(:login) do
        entered << Thread.current
        release.pop
        reauth_result
      end
      renewer.start
      worker = await_event(queue: entered)

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.01
      finish_thread(thread: run_in_background { renewer.stop(deadline: deadline) })
      expect(renewer.running?).to be true
      expect(auth_token).not_to have_received(:revoke_self)
      existing_threads = Thread.list
      3.times { renewer.start }
      expect(Thread.list - existing_threads).to be_empty
      renewer.request_stop
      release << true
      finish_thread(thread: worker)

      expect(renewer.running?).to be false
      expect(config).to eq(original_config)
      expect(vault_client.token).to eq('hvs.initial-token')
      expect(lease_manager).not_to have_received(:reissue_all)
      expect(Legion::Crypt::KerberosAuth).to have_received(:login).once

      allow(renewer).to receive(:sleep_duration).and_return(3600)
      allow(Legion::Crypt::KerberosAuth).to receive(:login).and_return(reauth_result)
      renewer.start
      expect(renewer.reauth_kerberos).to be true
      expect(vault_client.token).to eq('hvs.late-token')
      expect(config[:lease_duration]).to eq(300)
      expect(lease_manager).to have_received(:reissue_all).once
    end

    it 'wakes a sleeping worker without waiting for its scheduled renewal' do
      allow(renewer).to receive(:sleep_duration) do
        entered << true
        3600
      end
      allow(auth_token).to receive(:renew_self)
      renewer.start
      await_event(queue: entered)
      worker = renewer.instance_variable_get(:@thread)

      renewer.request_stop
      finish_thread(thread: worker)

      expect(renewer.running?).to be false
      expect(auth_token).not_to have_received(:renew_self)
      expect(auth_token).not_to have_received(:revoke_self)
    end
  end

  describe 'operation timeouts' do
    let(:blocked) { Queue.new }

    around do |example|
      vault_settings = Legion::Settings[:crypt][:vault]
      had_timeout = vault_settings.key?(:operation_timeout)
      previous_timeout = vault_settings[:operation_timeout]
      begin
        vault_settings[:operation_timeout] = 0.02
        example.run
      ensure
        if had_timeout
          vault_settings[:operation_timeout] = previous_timeout
        else
          vault_settings.delete(:operation_timeout)
        end
      end
    end

    it 'bounds renewal failure without changing the token configuration' do
      original_config = config.dup
      allow(auth_token).to receive(:renew_self) { blocked.pop }

      expect(finish_thread(thread: run_in_background { renewer.renew_token })).to be false
      expect(config).to eq(original_config)
      expect(vault_client.token).to eq('hvs.initial-token')
    end

    it 'bounds authentication failure without changing tokens or reissuing leases' do
      original_config = config.dup
      allow(Legion::Crypt::KerberosAuth).to receive(:login) { blocked.pop }

      expect(finish_thread(thread: run_in_background { renewer.reauth_kerberos })).to be false
      expect(config).to eq(original_config)
      expect(vault_client.token).to eq('hvs.initial-token')
      expect(lease_manager).not_to have_received(:reissue_all)
    end

    it 'bounds token revocation and remains restartable' do
      allow(auth_token).to receive(:revoke_self) { blocked.pop }
      renewer.start

      finish_thread(thread: run_in_background { renewer.stop })

      expect(renewer.running?).to be false
      expect(auth_token).to have_received(:revoke_self).once
      renewer.start
      expect(renewer.running?).to be true
    end
  end
end
