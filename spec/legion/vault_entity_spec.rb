# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_entity'

RSpec.describe Legion::Crypt::VaultEntity do
  let(:stubs) { Faraday::Adapter::Test::Stubs.new }
  let(:connection) { Faraday.new { |builder| builder.adapter :test, stubs } }
  let(:client) { Legion::Crypt::VaultClient.new(address: 'http://vault.example:8200', token: 'owner-token', namespace: 'owner') }
  let(:lease_manager) { instance_double(Legion::Crypt::LeaseManager, vault_logical: client.logical) }
  let(:principal_id) { 'user@example.com' }
  let(:canonical_name) { 'user-example-com' }
  let(:entity_id) { 'ent-abc-123' }
  let(:entity_body) { Legion::JSON.dump(data: { id: entity_id, name: "legion-#{canonical_name}" }) }

  before do
    connection
    allow(Faraday).to receive(:new).and_return(connection)
    allow(Legion::Crypt::LeaseManager).to receive(:instance).and_return(lease_manager)
  end

  after do
    client.shutdown
  end

  describe '.ensure_entity' do
    it 'creates the principal under the captured owner with authoritative Legion metadata' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") { [404, {}, '{}'] }
      stubs.put('/v1/identity/entity') do |env|
        expect(env.request_headers['X-Vault-Token']).to eq('owner-token')
        expect(env.request_headers['X-Vault-Namespace']).to eq('owner')
        expect(Legion::JSON.load(env.body)).to eq(
          name:     "legion-#{canonical_name}",
          metadata: { custom_key: 'custom', managed_by: 'legion', legion_principal_id: principal_id,
                      legion_canonical_name: canonical_name }
        )
        [200, {}, entity_body]
      end

      result = described_class.ensure_entity(principal_id: principal_id, canonical_name: canonical_name,
                                             metadata: { custom_key: 'custom', managed_by: 'untrusted' })

      expect(result).to eq(entity_id)
    end

    it 'returns an existing entity without issuing a creation request' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") { [200, {}, entity_body] }
      expect(client.logical).not_to receive(:write)

      expect(described_class.ensure_entity(principal_id: principal_id, canonical_name: canonical_name)).to eq(entity_id)
    end

    it 'returns nil when creation is forbidden' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") { [404, {}, '{}'] }
      stubs.put('/v1/identity/entity') { [403, {}, Legion::JSON.dump(errors: ['permission denied'])] }

      expect(described_class.ensure_entity(principal_id: principal_id, canonical_name: canonical_name)).to be_nil
    end

    it 'returns nil when the server acknowledges creation without entity data' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") { [404, {}, '{}'] }
      stubs.put('/v1/identity/entity') { [204, {}, ''] }

      expect(described_class.ensure_entity(principal_id: principal_id, canonical_name: canonical_name)).to be_nil
    end

    it 'reports network failures without raising to callers' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") { [404, {}, '{}'] }
      stubs.put('/v1/identity/entity') { raise Faraday::TimeoutError, 'network timeout' }
      allow(described_class).to receive(:handle_exception)

      expect(described_class.ensure_entity(principal_id: principal_id, canonical_name: canonical_name)).to be_nil
      expect(described_class).to have_received(:handle_exception).with(instance_of(Faraday::TimeoutError), anything)
    end
  end

  describe '.ensure_alias' do
    it 'links the supplied auth identity to its canonical entity under the captured owner' do
      stubs.put('/v1/identity/entity-alias') do |env|
        expect(env.request_headers['X-Vault-Namespace']).to eq('owner')
        expect(Legion::JSON.load(env.body)).to eq(name: principal_id, canonical_id: entity_id, mount_accessor: 'auth_jwt_abc123')
        [200, {}, Legion::JSON.dump(data: { id: 'alias-xyz-456' })]
      end

      response = described_class.ensure_alias(entity_id: entity_id, mount_accessor: 'auth_jwt_abc123', alias_name: principal_id)

      expect(response.data[:id]).to eq('alias-xyz-456')
    end

    it 'treats an existing alias as idempotent rather than an operational failure' do
      stubs.put('/v1/identity/entity-alias') do
        [400, {}, Legion::JSON.dump(errors: ['alias already exists for the combination of mount and alias name'])]
      end
      expect(described_class).not_to receive(:handle_exception)

      expect(described_class.ensure_alias(entity_id: entity_id, mount_accessor: 'auth_jwt_abc123', alias_name: principal_id)).to be_nil
    end

    it 'reports a forbidden alias write as a non-fatal failure' do
      stubs.put('/v1/identity/entity-alias') { [403, {}, Legion::JSON.dump(errors: ['permission denied'])] }
      allow(described_class).to receive(:handle_exception)

      expect(described_class.ensure_alias(entity_id: entity_id, mount_accessor: 'auth_jwt_abc123', alias_name: principal_id)).to be_nil
      expect(described_class).to have_received(:handle_exception).with(instance_of(Legion::Crypt::Vault::HTTPClientError), anything)
    end

    it 'reports server failures without raising to callers' do
      stubs.put('/v1/identity/entity-alias') { [503, {}, Legion::JSON.dump(errors: ['sealed'])] }
      allow(described_class).to receive(:handle_exception)

      expect(described_class.ensure_alias(entity_id: entity_id, mount_accessor: 'auth_jwt_abc123', alias_name: principal_id)).to be_nil
      expect(described_class).to have_received(:handle_exception).with(instance_of(Legion::Crypt::Vault::HTTPServerError), anything)
    end
  end

  describe '.find_by_name' do
    it 'decodes the entity ID from the HTTP response' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") { [200, {}, entity_body] }

      expect(described_class.find_by_name(canonical_name: canonical_name)).to eq(entity_id)
    end

    it 'returns nil for an entity that does not exist' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") { [404, {}, '{}'] }

      expect(described_class.find_by_name(canonical_name: canonical_name)).to be_nil
    end

    it 'returns nil when the response has no entity ID' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") { [200, {}, Legion::JSON.dump(data: { name: 'legion-foo' })] }

      expect(described_class.find_by_name(canonical_name: canonical_name)).to be_nil
    end

    it 'reports permission errors instead of mistaking their text for a 404' do
      stubs.get("/v1/identity/entity/name/legion-#{canonical_name}") do
        [403, {}, Legion::JSON.dump(errors: ['policy not found for this caller'])]
      end
      allow(described_class).to receive(:handle_exception)

      expect(described_class.find_by_name(canonical_name: canonical_name)).to be_nil
      expect(described_class).to have_received(:handle_exception).with(instance_of(Legion::Crypt::Vault::HTTPClientError), anything)
    end
  end
end
