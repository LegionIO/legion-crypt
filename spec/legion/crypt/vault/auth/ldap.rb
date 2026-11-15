# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault/auth/ldap'

RSpec.describe Legion::Crypt::Vault::Auth::LDAP do
  let(:client) { double('Vault client', logical: logical, auth_token: auth_token) }
  let(:logical) { double('Vault logical') }
  let(:auth_token) { double('AuthToken') }
  let(:auth_response) do
    Legion::Crypt::Vault::Client::Auth.new(data: { client_token: 'hvs.ldap-token', lease_duration: 3600, renewable: true,
                                                   policies: %w[admin], metadata: { username: 'mary@example.com' } })
  end
  let(:secret) { double('Secret', auth: auth_response) }

  before do
    Legion::Settings[:crypt][:vault][:clusters][:primary] = { auth_method: 'ldap', ldap: { auth_path: 'auth/ldap/login' } }
  end

  subject(:auth) { described_class.new(cluster_name: :primary) }

  it 'cannot re-authenticate on its own' do
    expect(auth.can_reauth?).to be(false)
  end

  it 'issues a grant from the LDAP login and stores it as the source-of-truth grant' do
    expect(logical).to receive(:write).with(path: 'auth/ldap/login/mary', data: { password: 'secret' }).and_return(secret)

    auth.authenticate(client: client, username: 'mary', password: 'secret')

    expect(auth.grant).to equal(auth_response)
    expect(auth.grant.metadata[:username]).to eq('mary@example.com')
  end

  it 'rejects a username that is not a single path segment' do
    expect { auth.authenticate(client: client, username: 'a/b', password: 'x') }.to raise_error(ArgumentError)
  end

  it 'raises AuthError when the login returns no auth data' do
    allow(logical).to receive(:write).and_return(double('Secret', auth: nil))

    expect { auth.authenticate(client: client, username: 'mary', password: 'x') }.to raise_error(Legion::Crypt::Vault::Auth::AuthError)
  end

  it 'wraps a Vault HTTP client error in AuthError' do
    allow(logical).to receive(:write).and_raise(Legion::Crypt::Vault::HTTPClientError.new(code: 403))

    expect { auth.authenticate(client: client, username: 'mary', password: 'x') }.to raise_error(Legion::Crypt::Vault::Auth::AuthError)
  end

  context 'after a grant has been issued' do
    before do
      allow(logical).to receive(:write).and_return(secret)
      auth.authenticate(client: client, username: 'mary', password: 'secret')
    end

    it 'replaces the grant with the renewed auth response on renew' do
      renewed = Legion::Crypt::Vault::Client::Auth.new(data: { client_token: 'hvs.renewed', lease_duration: 3600, renewable: true })
      allow(auth_token).to receive(:renew_self).and_return(double('Secret', auth: renewed))

      auth.renew(client: client)

      expect(auth.grant).to equal(renewed)
    end
  end
end
