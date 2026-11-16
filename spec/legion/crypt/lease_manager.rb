# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/lease_manager'

RSpec.describe Legion::Crypt::LeaseManager do
  subject(:manager) { described_class.instance }

  before { manager.reset! }
  after { manager.reset! }

  it 'is the process-wide Vault::Leases' do
    expect(manager).to be_a(Legion::Crypt::Vault::Leases)
    expect(described_class.instance).to equal(manager)
  end

  context 'with no Vault session' do
    it 'answers the cross-gem readers used by legion-data' do
      expect(manager.active_leases).to eq({})
      expect(manager.fetch(:postgresql, :username)).to be_nil
      expect(manager.reissue_lease(:postgresql)).to be(false)
    end

    it 'lets legion-settings leave a lease:// reference unresolved instead of raising' do
      settings = { data: { creds: { password: 'lease://postgresql#password' } } }

      expect { Legion::Settings::Resolver.resolve_secrets!(settings) }.not_to raise_error
      expect(settings[:data][:creds][:password]).to eq('lease://postgresql#password')
    end

    it 'resolves the reference on the next pass once a session has acquired the lease' do
      settings = { data: { creds: { password: 'lease://postgresql#password' } } }
      Legion::Settings::Resolver.resolve_secrets!(settings)
      response = double('Secret', data: { password: 'issued' }, lease_id: 'lease-1', lease_duration: 3600, renewable?: true)
      client = double('Vault client', logical: double('logical', read: response))

      manager.start(definitions: { postgresql: { path: 'postgresql/creds/node' } }, client: client)
      Legion::Settings::Resolver.resolve_secrets!(settings)

      expect(settings[:data][:creds][:password]).to eq('issued')
    end
  end
end
