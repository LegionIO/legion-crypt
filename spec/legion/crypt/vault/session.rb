# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault/session'

RSpec.describe Legion::Crypt::Vault::Session do
  let(:client) { double('Vault client') }
  let(:cluster_name) { :primary }
  let(:old_grant) do
    Legion::Crypt::Vault::Client::Auth.new(data: { client_token: 'old-token', lease_duration: 3600, renewable: true,
                                                   metadata: { username: 'user@EXAMPLE.COM' } })
  end
  let(:new_grant) do
    Legion::Crypt::Vault::Client::Auth.new(data: { client_token: 'new-token', lease_duration: 3600, renewable: true,
                                                   metadata: { username: 'user@EXAMPLE.COM' } })
  end
  let(:new_expires) { Time.now + 3600 }

  subject(:session) { described_class.new(cluster_name: cluster_name, client: client) }

  before { allow(session).to receive(:crypt_stopping?).and_return(false) }

  describe '#principal' do
    it 'returns the username from the current grant metadata' do
      session.instance_variable_set(:@auth, double('auth', grant: old_grant))
      expect(session.principal).to eq('user@EXAMPLE.COM')
    end

    it 'is nil before a grant is issued' do
      expect(session.principal).to be_nil
    end
  end

  describe '#handoff (re-auth -> reissue -> commit/rollback)' do
    let(:stub_auth) do
      auth = double('auth', grant: old_grant, can_reauth?: true)
      allow(auth).to receive(:reauth) { allow(auth).to receive(:grant).and_return(new_grant) }
      auth
    end
    let(:stub_leases) { double('leases') }

    before do
      session.instance_variable_set(:@auth, stub_auth)
      session.instance_variable_set(:@leases, stub_leases)
      session.instance_variable_set(:@current_token, old_grant.client_token)
      session.instance_variable_set(:@started, true)
      allow(Legion::Crypt).to receive(:publish_vault_grant).and_return(new_expires)
    end

    it 'reissues under the new token and revokes the old token on success' do
      expect(stub_leases).to receive(:reissue_all).and_return(true)
      expect(Legion::Crypt).to receive(:revoke_vault_token).with(client: client, token: old_grant.client_token)

      expect(session.send(:handoff)).to eq(:renewed)
    end

    it 'restores the old token and does not revoke it when the reissue fails' do
      expect(stub_leases).to receive(:reissue_all).and_return(false)
      expect(Legion::Crypt).not_to receive(:revoke_vault_token)

      expect(session.send(:handoff)).to eq(:failed)
      expect(session.instance_variable_get(:@current_token)).to eq(old_grant.client_token)
    end
  end

  describe '#stop' do
    it 'shuts down the leases and revokes the current token' do
      session.instance_variable_set(:@current_token, old_grant.client_token)
      session.instance_variable_set(:@expires_at, Time.now + 3600)
      stub_leases = double('leases')
      session.instance_variable_set(:@leases, stub_leases)
      allow(stub_leases).to receive(:request_stop)
      expect(stub_leases).to receive(:shutdown).with(deadline: anything)
      expect(Legion::Crypt).to receive(:revoke_vault_token).with(client: client, token: old_grant.client_token)

      session.stop(deadline: Time.now + 5)
    end
  end
end
