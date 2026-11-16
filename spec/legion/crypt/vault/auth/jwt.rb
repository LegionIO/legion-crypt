# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault/auth/jwt'

RSpec.describe Legion::Crypt::Vault::Auth::JWT do
  let(:client) { double('Vault client', logical: logical, auth_token: auth_token) }
  let(:logical) { double('Vault logical') }
  let(:auth_token) { double('AuthToken') }
  let(:auth_response) do
    Legion::Crypt::Vault::Client::Auth.new(data: { client_token: 'hvs.jwt-token', lease_duration: 3600, renewable: true,
                                                   policies: %w[worker], metadata: { username: 'legion-worker' } })
  end
  let(:secret) { double('Secret', auth: auth_response) }

  before do
    Legion::Settings[:crypt][:vault][:clusters][:primary] = { auth_method: 'jwt', jwt: { auth_path: 'auth/jwt/login', role: 'legion-worker' } }
  end

  subject(:auth) { described_class.new(cluster_name: :primary) }

  it 'cannot re-authenticate on its own' do
    expect(auth.can_reauth?).to be(false)
  end

  it 'presents the JWT to the configured role and stores the grant' do
    expect(logical).to receive(:write)
      .with(path: 'auth/jwt/login', data: { role: 'legion-worker', jwt: 'signed.jwt.here' })
      .and_return(secret)

    auth.authenticate(client: client, jwt: 'signed.jwt.here')

    expect(auth.grant).to equal(auth_response)
  end

  it 'raises AuthError when the login returns no auth data' do
    allow(logical).to receive(:write).and_return(double('Secret', auth: nil))

    expect { auth.authenticate(client: client, jwt: 'signed.jwt.here') }.to raise_error(Legion::Crypt::Vault::Auth::AuthError)
  end

  it 'wraps a Vault HTTP error in AuthError' do
    allow(logical).to receive(:write).and_raise(Legion::Crypt::Vault::HTTPServerError.new(code: 503))

    expect { auth.authenticate(client: client, jwt: 'signed.jwt.here') }.to raise_error(Legion::Crypt::Vault::Auth::AuthError)
  end
end
