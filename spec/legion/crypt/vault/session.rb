# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault/session'

RSpec.describe Legion::Crypt::Vault::Session do
  let(:auth_token) { double('AuthToken') }
  let(:client) { double('Vault client', auth_token: auth_token) }
  let(:cluster_name) { :primary }
  let(:leases) { nil }
  let(:strategy) { double('auth strategy', can_reauth?: true) }
  let(:initial_grant) { grant(token: 'old-token') }
  let(:published) { [] }
  let(:revoked) { [] }

  subject(:session) { described_class.new(cluster_name: cluster_name, client: client, leases: leases) }

  def grant(token:, renewable: true, ttl: 3600)
    Legion::Crypt::Vault::Client::Auth.new(data: { client_token: token, lease_duration: ttl, renewable: renewable,
                                                   metadata: { username: 'user@EXAMPLE.COM' } })
  end

  before do
    Legion::Settings[:crypt][:vault][:clusters] = { primary: { auth_method: 'kerberos', token: nil } }
    allow(client).to receive(:token=)
    allow(Legion::Crypt::Vault::Auth::Kerberos).to receive(:new).and_return(strategy)
    allow(strategy).to receive(:authenticate).and_return(initial_grant)
    allow(Legion::Crypt).to receive(:publish_vault_grant) do |grant:, issued_at: Time.now, **options|
      published << options.merge(token: grant[:token])
      issued_at + grant[:lease_duration] if grant[:lease_duration]
    end
    allow(Legion::Crypt).to receive(:revoke_vault_token) { |token:, **| revoked << token }
    allow(Legion::Crypt).to receive(:disconnect_vault_grant)
    allow(Thread).to receive(:new).and_return(instance_double(Thread, alive?: true, :name= => nil, join: nil))
  end

  describe '#start' do
    it 'authenticates a Kerberos cluster through its strategy and publishes the grant' do
      expect(session.start).to be(true)

      expect(strategy).to have_received(:authenticate).with(client: client)
      expect(published.last).to include(token: 'old-token', auth_method: 'kerberos', cluster_name: :primary)
      expect(session.principal).to eq('user@EXAMPLE.COM')
    end

    it 'reports a failed authentication without raising' do
      allow(strategy).to receive(:authenticate).and_raise(Legion::Crypt::Vault::Auth::AuthError, 'denied')

      expect(session.start).to be(false)
      expect(session.principal).to be_nil
    end

    context 'when the session owns the leases' do
      let(:leases) { instance_double(Legion::Crypt::Vault::Leases, start: nil, start_renewal_thread: nil) }

      it 'starts lease acquisition and lease renewal even with no static lease definitions' do
        session.start

        expect(leases).to have_received(:start).with(definitions: nil, client: client)
        expect(leases).to have_received(:start_renewal_thread)
      end
    end

    context 'with a static configured token' do
      before do
        Legion::Settings[:crypt][:vault][:clusters] = { primary: { auth_method: nil, token: 'static-token' } }
        allow(client).to receive(:sys).and_return(double('sys', health_status: double('health', initialized?: true)))
      end

      it 'adopts the token without an auth strategy and never revokes it on stop' do
        session.start
        session.stop(deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1)

        expect(published.last).to include(token: 'static-token', auth_method: 'token')
        expect(revoked).to be_empty
      end
    end
  end

  describe '#login' do
    before do
      Legion::Settings[:crypt][:vault][:clusters] = { primary: { auth_method: 'ldap', token: nil } }
      allow(Legion::Crypt::Vault::Auth::LDAP).to receive(:new).and_return(strategy)
    end

    it 'raises a failed login to the caller' do
      allow(strategy).to receive(:authenticate).and_raise(Legion::Crypt::Vault::Auth::AuthError, 'denied')
      session.start

      expect { session.login(username: 'mary', password: 'wrong') }.to raise_error(Legion::Crypt::Vault::Auth::AuthError)
    end

    it 'authenticates with the given credentials and returns the grant as a Hash' do
      session.start

      result = session.login(username: 'mary', password: 'secret')

      expect(strategy).to have_received(:authenticate).with(client: client, username: 'mary', password: 'secret')
      expect(result).to include(token: 'old-token', renewable: true, lease_duration: 3600)
    end
  end

  describe 'token maintenance' do
    before { session.start }

    it 'renews a token Vault reported as renewable' do
      allow(auth_token).to receive(:renew_self).and_return(double('Secret', auth: grant(token: 'old-token', ttl: 7200)))

      expect(session.send(:maintain_token)).to eq(:renewed)
      expect(published.last).to include(token: 'old-token', current_token: 'old-token')
      expect(strategy).to have_received(:authenticate).once
    end

    context 'when Vault reported the token as not renewable' do
      let(:initial_grant) { grant(token: 'old-token', renewable: false) }

      it 'never attempts a renewal and re-authenticates instead when the strategy can' do
        allow(auth_token).to receive(:renew_self)
        allow(strategy).to receive(:reauth).and_return(grant(token: 'new-token', renewable: false))

        expect(session.send(:maintain_token)).to eq(:renewed)
        expect(auth_token).not_to have_received(:renew_self)
        expect(revoked).to eq(['old-token'])
      end

      it 'waits for expiry when the strategy cannot re-authenticate' do
        allow(auth_token).to receive(:renew_self)
        allow(strategy).to receive(:can_reauth?).and_return(false)

        expect(session.send(:maintain_token)).to eq(:pending)
        expect(auth_token).not_to have_received(:renew_self)
      end
    end
  end

  describe '#handoff (re-auth -> reissue -> commit/rollback)' do
    let(:leases) { instance_double(Legion::Crypt::Vault::Leases, start: nil, start_renewal_thread: nil) }

    before do
      session.start
      allow(strategy).to receive(:reauth).and_return(grant(token: 'new-token'))
    end

    it 'reissues under the new token and revokes the old token on success' do
      allow(leases).to receive(:reissue_all).and_return(true)

      expect(session.send(:handoff)).to eq(:renewed)
      expect(published.last).to include(token: 'new-token', current_token: 'old-token')
      expect(revoked).to eq(['old-token'])
    end

    it 'revokes the candidate and restores the old grant with its original expiry when the reissue fails' do
      original_expiry = session.instance_variable_get(:@expires_at)
      allow(leases).to receive(:reissue_all).and_return(false)

      expect(session.send(:handoff)).to eq(:failed)
      expect(revoked).to eq(['new-token'])
      expect(published.last).to include(token: 'old-token', current_token: nil)
      expect(session.instance_variable_get(:@expires_at)).to be_within(0.001).of(original_expiry)
    end

    it 'finishes without raising when the cluster rejects the new grant' do
      allow(Legion::Crypt).to receive(:publish_vault_grant).and_raise(Legion::Crypt::Vault::GrantRejectedError, 'changed')

      expect(session.send(:handoff)).to eq(:finished)
    end
  end

  describe '#stop' do
    let(:leases) { instance_double(Legion::Crypt::Vault::Leases, start: nil, start_renewal_thread: nil, request_stop: nil) }
    let(:deadline) { Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1 }

    before { session.start }

    it 'shuts down the leases and then revokes the minted token' do
      expect(leases).to receive(:shutdown).with(deadline: anything).ordered.and_return(true)
      expect(Legion::Crypt).to receive(:revoke_vault_token).with(client: client, token: 'old-token').ordered

      expect(session.stop(deadline: deadline)).to be(true)
    end

    it 'reports incomplete cleanup when the token could not be revoked' do
      allow(leases).to receive(:shutdown).and_return(true)
      allow(Legion::Crypt).to receive(:revoke_vault_token).and_raise(Legion::Crypt::Vault::HTTPClientError.new(code: 403))

      expect(session.stop(deadline: deadline)).to be(false)
    end

    it 'reports incomplete cleanup when leases were left behind' do
      allow(leases).to receive(:shutdown).and_return(false)

      expect(session.stop(deadline: deadline)).to be(false)
      expect(revoked).to eq(['old-token'])
    end
  end

  describe 'provisional grant cleanup with a live cluster client' do
    let(:client) { Legion::Crypt.vault_client(:primary) }

    before do
      allow(client).to receive(:token=).and_call_original
      allow(Legion::Crypt).to receive(:publish_vault_grant).and_call_original
    end

    after { Legion::Crypt.clear_vault_clients }

    def replace_cluster_address
      replacement = Marshal.load(Marshal.dump(Legion::Settings[:crypt]))
      replacement[:vault][:clusters][:primary][:address] = 'replacement.example.com'
      Legion::Settings.set_prop(:crypt, replacement)
    end

    it 'revokes a Kerberos startup grant rejected after settings reconstruction' do
      allow(strategy).to receive(:authenticate) do
        replace_cluster_address
        initial_grant
      end

      expect(session.start).to be(false)
      expect(revoked).to eq(['old-token'])
      expect(session.instance_variable_get(:@grant)).to be_nil
    end

    it 'revokes a Kerberos startup grant issued after stop was requested' do
      allow(strategy).to receive(:authenticate) do
        session.request_stop
        initial_grant
      end

      expect(session.start).to be(false)
      expect(revoked).to eq(['old-token'])
      expect(session.instance_variable_get(:@grant)).to be_nil
    end

    it 'revokes a rejected re-auth grant and retains the previous grant and expiry' do
      session.start
      previous_expiry = session.instance_variable_get(:@expires_at)
      allow(strategy).to receive(:reauth) do
        replace_cluster_address
        grant(token: 'new-token')
      end

      expect(session.send(:handoff)).to eq(:finished)
      expect(session.instance_variable_get(:@grant)).to equal(initial_grant)
      expect(session.instance_variable_get(:@current_token)).to eq('old-token')
      expect(session.instance_variable_get(:@expires_at)).to eq(previous_expiry)
      expect(revoked).to eq(['new-token'])

      session.stop(deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1)
      expect(revoked).to eq(%w[new-token old-token])
    end

    it 'revokes a login grant rejected after the client is replaced' do
      Legion::Settings[:crypt][:vault][:clusters][:primary][:auth_method] = 'ldap'
      allow(Legion::Crypt::Vault::Auth::LDAP).to receive(:new).and_return(strategy)
      session.start
      allow(strategy).to receive(:authenticate) do
        Legion::Crypt.clear_vault_clients
        Legion::Crypt.vault_client(:primary)
        grant(token: 'new-token')
      end

      expect { session.login(username: 'user', password: 'secret') }.to raise_error(Legion::Crypt::Vault::GrantRejectedError)
      expect(revoked).to eq(['new-token'])
      expect(session.instance_variable_get(:@grant)).to be_nil
    end

    it 'revokes a grant issued after stop was requested and preserves the active token' do
      session.start
      allow(strategy).to receive(:reauth) do
        session.request_stop
        grant(token: 'new-token')
      end

      expect(session.send(:handoff)).to eq(:finished)
      expect(revoked).to eq(['new-token'])
      expect(session.instance_variable_get(:@current_token)).to eq('old-token')
      session.stop(deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1)
      expect(revoked).to eq(%w[new-token old-token])
    end

    it 'revokes a login grant issued after stop was requested' do
      Legion::Settings[:crypt][:vault][:clusters][:primary][:auth_method] = 'ldap'
      allow(Legion::Crypt::Vault::Auth::LDAP).to receive(:new).and_return(strategy)
      session.start
      allow(strategy).to receive(:authenticate) do
        session.request_stop
        grant(token: 'new-token')
      end

      expect(session.login(username: 'user', password: 'secret')).to be_nil
      expect(revoked).to eq(['new-token'])
    end

    it 'reports an incomplete cleanup at error level without raising from handoff' do
      session.start
      allow(strategy).to receive(:reauth) do
        replace_cluster_address
        grant(token: 'new-token')
      end
      allow(Legion::Crypt).to receive(:revoke_vault_token).and_raise(Legion::Crypt::Vault::HTTPServerError.new(code: 503))
      allow(session).to receive(:handle_exception).and_call_original

      expect(session.send(:handoff)).to eq(:finished)
      expect(session).to have_received(:handle_exception).with(
        instance_of(Legion::Crypt::Vault::HTTPServerError), level: :error,
        operation: 'crypt.vault_session.revoke', cluster_name: :primary, outcome: 'incomplete'
      )
    end
  end
end
