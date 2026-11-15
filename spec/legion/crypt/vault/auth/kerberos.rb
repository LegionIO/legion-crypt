# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault/auth/kerberos'

RSpec.describe Legion::Crypt::Vault::Auth::Kerberos do
  let(:client) { double('Vault client') }
  let(:raw_response) do
    { auth: { client_token: 'hvs.krb-token', lease_duration: 3600, renewable: true,
              policies: %w[admin], metadata: { username: 'mitch@EXAMPLE.COM' } } }
  end

  before do
    Legion::Settings[:crypt][:vault][:clusters][:primary] = { auth_method: 'kerberos',
                                                              kerberos:    { service_principal: 'HTTP/vault.example',
                                                                             auth_path:         'auth/kerberos/login' } }
    allow(auth).to receive(:spnego_available?).and_return(true)
    allow(auth).to receive(:obtain_spnego_token).and_return('spnego-token')
  end

  subject(:auth) { described_class.new(cluster_name: :primary) }

  it 'can re-authenticate from the ticket cache' do
    expect(auth.can_reauth?).to be(true)
  end

  it 'sends the SPNEGO token as the Authorization header and stores the grant' do
    expect(client).to receive(:put)
      .with(path: 'auth/kerberos/login', body: '{}', headers: { 'Authorization' => 'Negotiate spnego-token' })
      .and_return(raw_response)

    auth.authenticate(client: client)

    expect(auth.grant.client_token).to eq('hvs.krb-token')
    expect(auth.grant.metadata[:username]).to eq('mitch@EXAMPLE.COM')
  end

  it 'raises AuthError when the service principal is not configured' do
    allow(client).to receive(:put)
    Legion::Settings[:crypt][:vault][:clusters][:primary][:kerberos] = { service_principal: nil }

    expect { auth.authenticate(client: client) }.to raise_error(Legion::Crypt::Vault::Auth::AuthError)
  end

  it 'raises GemMissingError when the SPNEGO helper is unavailable' do
    allow(auth).to receive(:spnego_available?).and_return(false)

    expect { auth.authenticate(client: client) }.to raise_error(Legion::Crypt::Vault::Auth::Kerberos::GemMissingError)
  end

  it 'raises AuthError when the exchange returns no auth data' do
    allow(client).to receive(:put).and_return({ auth: nil })

    expect { auth.authenticate(client: client) }.to raise_error(Legion::Crypt::Vault::Auth::AuthError)
  end

  it 'wraps a Vault HTTP client error in AuthError' do
    allow(client).to receive(:put).and_raise(Legion::Crypt::Vault::HTTPClientError.new(code: 403))

    expect { auth.authenticate(client: client) }.to raise_error(Legion::Crypt::Vault::Auth::AuthError)
  end

  it 're-runs the ticket-cache exchange on reauth' do
    expect(client).to receive(:put).twice.and_return(raw_response)

    auth.authenticate(client: client)
    auth.reauth(client: client)

    expect(auth.grant.client_token).to eq('hvs.krb-token')
  end
end
