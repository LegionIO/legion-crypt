# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt'

RSpec.describe Legion::Crypt::LdapAuth do
  let(:crypt) { Legion::Crypt }
  let(:configuration) { Legion::Crypt::Settings.default.merge(save_private_key: false) }
  let(:cluster_one) { { protocol: 'https', address: 'vault-one.example.com', port: 8200, auth_method: 'ldap', connected: false } }
  let(:cluster_two) { { protocol: 'https', address: 'vault-two.example.com', port: 8200, auth_method: 'ldap', connected: false } }
  let(:client) { crypt.vault_client(:one) }
  let(:logical) { instance_double(Vault::Logical) }
  let(:auth_token) { double('AuthToken') }
  let(:login_secret) { ldap_secret(token: 'ldap-token', ttl: 0.2, renewable: true) }

  before do
    crypt.shutdown
    configuration[:vault].merge!(token: nil, connected: false, default: :one, clusters: { one: cluster_one }, leases: {})
    allow(Legion::Settings).to receive(:[]).and_call_original
    allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
    allow(client).to receive(:logical).and_return(logical)
    allow(client).to receive(:auth_token).and_return(auth_token)
    allow(logical).to receive(:write).and_return(login_secret)
    allow(logical).to receive(:read).and_return(double('Secret', data: { owner: 'one' }, lease_id: nil))
    expect(Legion::Crypt::KerberosAuth).not_to receive(:login)
  end

  after { crypt.shutdown }

  def ldap_secret(token:, ttl:, renewable:)
    double('Secret', auth: double('Auth', client_token: token, lease_duration: ttl, renewable?: renewable, policies: ['default']))
  end

  it 'starts renewal after Crypt.start and remains usable beyond the initial token expiry' do
    renewed = Queue.new
    allow(auth_token).to receive(:renew_self) do
      renewed << true
      ldap_secret(token: 'ldap-token', ttl: 2, renewable: true)
    end
    crypt.start
    result = crypt.ldap_login(cluster_name: 'one', username: 'jdoe', password: 'one-use-password')
    original_expiry = cluster_one[:expires_at]
    Timeout.timeout(1) { renewed.pop }
    sleep([original_expiry - Time.now + 0.02, 0].max)

    expect(result[:token]).to eq('ldap-token')
    expect(crypt.read('secret/application', cluster_name: :one)).to eq(owner: 'one')
    expect(crypt.vault_connected?).to be(true)
    expect(cluster_one[:expires_at]).to be > original_expiry
    expect(cluster_one.to_s).not_to include('one-use-password')
  end

  it 'keeps a nonrenewable token usable until expiry and then requires login' do
    allow(logical).to receive(:write).and_return(ldap_secret(token: 'finite-token', ttl: 0.1, renewable: false))
    expect(auth_token).not_to receive(:renew_self)
    crypt.ldap_login(cluster_name: :one, username: 'jdoe', password: 'secret')
    configuration[:vault][:connected] = true
    expect(crypt.read('secret/application')).to eq(owner: 'one')
    worker = Thread.list.find { |thread| thread.name == 'vault-renewer-one' }
    expect(worker.join(1)).to eq(worker)

    expect(crypt.vault_connected?).to be(false)
    expect(cluster_one[:connected]).to be(false)
    expect(cluster_one[:relogin_required]).to be(true)
    expect { crypt.read('secret/application') }.to raise_error(ArgumentError, /not connected/)
    expect { crypt.get('secret/application', cluster_name: :one) }.to raise_error(ArgumentError, /not connected/)
  end

  it 'immediately requires login after terminal renewal rejection' do
    rejection = Vault::HTTPClientError.new('https://vault-one.example.com', double('Response', code: '403'), ['permission denied'])
    allow(auth_token).to receive(:renew_self).and_raise(rejection)
    crypt.ldap_login(cluster_name: :one, username: 'jdoe', password: 'secret')
    worker = Thread.list.find { |thread| thread.name == 'vault-renewer-one' }
    expect(worker.join(1)).to eq(worker)

    expect(cluster_one[:expires_at]).to be > Time.now
    expect(crypt.connected_clusters).to be_empty
    expect(cluster_one[:relogin_required]).to be(true)
    expect { crypt.read('secret/application') }.to raise_error(ArgumentError, /not connected/)
  end

  it 'renews through the authenticated cluster without changing another cluster token' do
    configuration[:vault][:clusters][:two] = cluster_two
    second_client = crypt.vault_client(:two)
    second_logical = instance_double(Vault::Logical)
    second_auth = double('SecondAuthToken')
    renewed = Queue.new
    allow(second_client).to receive(:logical).and_return(second_logical)
    allow(second_client).to receive(:auth_token).and_return(second_auth)
    allow(second_logical).to receive(:write).and_return(ldap_secret(token: 'second-token', ttl: 0.1, renewable: true))
    allow(second_auth).to receive(:renew_self) do
      renewed << true
      ldap_secret(token: 'second-token', ttl: 5, renewable: false)
    end
    expect(auth_token).not_to receive(:renew_self)
    crypt.ldap_login(cluster_name: :two, username: 'jdoe', password: 'secret')
    Timeout.timeout(1) { renewed.pop }

    expect(crypt.connected_clusters.keys).to eq([:two])
    expect(client.token).to be_nil
    expect(second_client.token).to eq('second-token')
  end

  it 'isolates login failures and redacts passwords from batch error results' do
    configuration[:vault][:clusters][:two] = cluster_two
    second_client = crypt.vault_client(:two)
    second_logical = instance_double(Vault::Logical)
    allow(second_client).to receive(:logical).and_return(second_logical)
    allow(second_logical).to receive(:write).and_return(ldap_secret(token: 'second-token', ttl: 60, renewable: false))
    allow(logical).to receive(:write).and_raise(IOError, 'authentication rejected one-use-password')
    messages = []
    logger = double('Logger', info: nil)
    allow(logger).to receive(:error) { |message| messages << message }
    allow(logger).to receive(:warn) { |message| messages << message }
    allow(crypt).to receive(:log).and_return(logger)

    results = crypt.ldap_login_all(username: 'jdoe', password: 'one-use-password')

    expect(results[:one]).to eq(error: 'authentication rejected [REDACTED]')
    expect(results[:two][:token]).to eq('second-token')
    expect(crypt.connected_clusters.keys).to eq([:two])
    expect(messages.join).not_to include('one-use-password')
  end
end
