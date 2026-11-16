# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault/leases'

RSpec.describe Legion::Crypt::Vault::Leases do
  let(:client) { double('Vault client', logical: logical, sys: sys) }
  let(:logical) { double('Vault logical') }
  let(:sys) { double('Vault sys') }
  let(:lease_response) do
    double('Secret', data: { username: 'db_user', password: 'db_pass' }, lease_id: 'lease-1',
           lease_duration: 3600, renewable?: true)
  end

  subject(:leases) { described_class.new }

  describe '#start' do
    it 'acquires each defined lease and exposes its data' do
      expect(logical).to receive(:read).with(path: 'postgresql/creds/node').and_return(lease_response)

      leases.start(definitions: { postgresql: { path: 'postgresql/creds/node' } }, client: client)

      expect(leases.active_leases.keys).to eq([:postgresql])
      expect(leases.lease_data(:postgresql)).to eq(username: 'db_user', password: 'db_pass')
      expect(leases.fetch(:postgresql, :username)).to eq('db_user')
      expect(leases.fetched_count).to eq(1)
    end

    it 'returns nil data for a lease that was not acquired' do
      leases.start(definitions: {}, client: client)
      expect(leases.lease_data(:missing)).to be_nil
      expect(leases.fetch(:missing, :username)).to be_nil
    end
  end

  describe '#reissue_all' do
    before do
      allow(sys).to receive(:revoke)
      allow(logical).to receive(:read).with(path: 'postgresql/creds/node').and_return(lease_response)
      leases.start(definitions: { postgresql: { path: 'postgresql/creds/node' } }, client: client)
    end

    it 're-acquires the leases issued through the client and exposes the new credentials' do
      rotated = double('Secret', data: { username: 'db_user_2', password: 'db_pass_2' }, lease_id: 'lease-2',
                      lease_duration: 3600, renewable?: true)
      expect(logical).to receive(:read).with(path: 'postgresql/creds/node').and_return(rotated)

      expect(leases.reissue_all(client: client)).to be(true)
      expect(leases.fetch(:postgresql, :username)).to eq('db_user_2')
    end

    it 'is a no-op for a client that did not issue the lease' do
      other = double('other client', logical: double('other logical'))
      expect(logical).not_to receive(:read)

      expect(leases.reissue_all(client: other)).to be(true)
    end
  end

  describe '#shutdown' do
    it 'revokes the owned leases' do
      allow(logical).to receive(:read).with(path: 'postgresql/creds/node').and_return(lease_response)
      leases.start(definitions: { postgresql: { path: 'postgresql/creds/node' } }, client: client)

      expect(sys).to receive(:revoke).with(lease_id: 'lease-1')
      expect(leases.shutdown).to be(true)
    end
  end
end
