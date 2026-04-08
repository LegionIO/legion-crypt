# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_entity'

RSpec.describe Legion::Crypt::VaultEntity do
  let(:vault_logical)   { instance_double('Vault::Logical') }
  let(:lease_manager)   { instance_double('Legion::Crypt::LeaseManager') }

  let(:principal_id)    { 'user@example.com' }
  let(:canonical_name)  { 'user-example-com' }
  let(:entity_id)       { 'ent-abc-123' }
  let(:mount_accessor)  { 'auth_jwt_abc123' }
  let(:alias_name)      { 'user@example.com' }

  let(:entity_response) do
    double('Vault::Secret', data: { id: entity_id, name: "legion-#{canonical_name}" })
  end

  let(:alias_response) do
    double('Vault::Secret', data: { id: 'alias-xyz-456' })
  end

  before do
    stub_const('Vault::HTTPClientError', Class.new(StandardError))

    allow(Legion::Crypt::LeaseManager).to receive(:instance).and_return(lease_manager)
    allow(lease_manager).to receive(:vault_logical).and_return(vault_logical)

    allow(vault_logical).to receive(:read).and_return(nil)
    allow(vault_logical).to receive(:write).and_return(nil)
  end

  # ---------------------------------------------------------------------------
  describe '.ensure_entity' do
    context 'when no entity exists yet' do
      before do
        allow(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_return(nil)

        allow(vault_logical).to receive(:write)
          .with('identity/entity', anything)
          .and_return(entity_response)
      end

      it 'creates an entity and returns its ID' do
        result = described_class.ensure_entity(
          principal_id:   principal_id,
          canonical_name: canonical_name
        )
        expect(result).to eq(entity_id)
      end

      it 'writes to identity/entity with the legion- prefix' do
        expect(vault_logical).to receive(:write).with(
          'identity/entity',
          hash_including(name: "legion-#{canonical_name}")
        ).and_return(entity_response)

        described_class.ensure_entity(principal_id: principal_id, canonical_name: canonical_name)
      end

      it 'includes standard managed_by metadata' do
        expect(vault_logical).to receive(:write).with(
          'identity/entity',
          hash_including(
            metadata: hash_including(
              managed_by:            'legion',
              legion_principal_id:   principal_id,
              legion_canonical_name: canonical_name
            )
          )
        ).and_return(entity_response)

        described_class.ensure_entity(principal_id: principal_id, canonical_name: canonical_name)
      end

      it 'merges caller-supplied metadata with standard metadata' do
        expect(vault_logical).to receive(:write).with(
          'identity/entity',
          hash_including(
            metadata: hash_including(
              custom_key:          'custom_value',
              legion_principal_id: principal_id,
              managed_by:          'legion'
            )
          )
        ).and_return(entity_response)

        described_class.ensure_entity(
          principal_id:   principal_id,
          canonical_name: canonical_name,
          metadata:       { custom_key: 'custom_value' }
        )
      end
    end

    context 'when entity already exists' do
      before do
        allow(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_return(entity_response)
      end

      it 'returns the existing entity ID without creating a new one' do
        expect(vault_logical).not_to receive(:write).with('identity/entity', anything)

        result = described_class.ensure_entity(
          principal_id:   principal_id,
          canonical_name: canonical_name
        )
        expect(result).to eq(entity_id)
      end
    end

    context 'when Vault raises HTTPClientError on write' do
      before do
        allow(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_return(nil)

        allow(vault_logical).to receive(:write)
          .with('identity/entity', anything)
          .and_raise(Vault::HTTPClientError, 'permission denied')
      end

      it 'returns nil instead of raising' do
        result = described_class.ensure_entity(
          principal_id:   principal_id,
          canonical_name: canonical_name
        )
        expect(result).to be_nil
      end
    end

    context 'when Vault raises an unexpected StandardError' do
      before do
        allow(vault_logical).to receive(:read).and_return(nil)
        allow(vault_logical).to receive(:write)
          .with('identity/entity', anything)
          .and_raise(StandardError, 'network timeout')
      end

      it 'returns nil instead of raising' do
        result = described_class.ensure_entity(
          principal_id:   principal_id,
          canonical_name: canonical_name
        )
        expect(result).to be_nil
      end
    end

    context 'when write response has no data' do
      before do
        allow(vault_logical).to receive(:read).and_return(nil)
        allow(vault_logical).to receive(:write)
          .with('identity/entity', anything)
          .and_return(double('Vault::Secret', data: nil))
      end

      it 'returns nil' do
        result = described_class.ensure_entity(
          principal_id:   principal_id,
          canonical_name: canonical_name
        )
        expect(result).to be_nil
      end
    end

    context 'when write returns nil response' do
      before do
        allow(vault_logical).to receive(:read).and_return(nil)
        allow(vault_logical).to receive(:write)
          .with('identity/entity', anything)
          .and_return(nil)
      end

      it 'returns nil' do
        result = described_class.ensure_entity(
          principal_id:   principal_id,
          canonical_name: canonical_name
        )
        expect(result).to be_nil
      end
    end
  end

  # ---------------------------------------------------------------------------
  describe '.ensure_alias' do
    context 'when alias does not exist' do
      before do
        allow(vault_logical).to receive(:write)
          .with('identity/entity-alias', anything)
          .and_return(alias_response)
      end

      it 'writes to identity/entity-alias and returns the response' do
        result = described_class.ensure_alias(
          entity_id:      entity_id,
          mount_accessor: mount_accessor,
          alias_name:     alias_name
        )
        expect(result).to eq(alias_response)
      end

      it 'passes the correct params to Vault' do
        expect(vault_logical).to receive(:write).with(
          'identity/entity-alias',
          name:           alias_name,
          canonical_id:   entity_id,
          mount_accessor: mount_accessor
        ).and_return(alias_response)

        described_class.ensure_alias(
          entity_id:      entity_id,
          mount_accessor: mount_accessor,
          alias_name:     alias_name
        )
      end
    end

    context 'when alias already exists (idempotent)' do
      before do
        err = Vault::HTTPClientError.new('alias already exists for the combination of mount and alias name')
        allow(vault_logical).to receive(:write)
          .with('identity/entity-alias', anything)
          .and_raise(err)
      end

      it 'returns nil without raising' do
        result = described_class.ensure_alias(
          entity_id:      entity_id,
          mount_accessor: mount_accessor,
          alias_name:     alias_name
        )
        expect(result).to be_nil
      end
    end

    context 'when Vault raises a different HTTPClientError' do
      before do
        err = Vault::HTTPClientError.new('permission denied')
        allow(vault_logical).to receive(:write)
          .with('identity/entity-alias', anything)
          .and_raise(err)
      end

      it 're-raises the error' do
        expect do
          described_class.ensure_alias(
            entity_id:      entity_id,
            mount_accessor: mount_accessor,
            alias_name:     alias_name
          )
        end.to raise_error(Vault::HTTPClientError, 'permission denied')
      end
    end

    context 'when Vault raises an unexpected StandardError' do
      before do
        allow(vault_logical).to receive(:write)
          .with('identity/entity-alias', anything)
          .and_raise(StandardError, 'connection reset')
      end

      it 'returns nil without raising' do
        result = described_class.ensure_alias(
          entity_id:      entity_id,
          mount_accessor: mount_accessor,
          alias_name:     alias_name
        )
        expect(result).to be_nil
      end
    end
  end

  # ---------------------------------------------------------------------------
  describe '.find_by_name' do
    context 'when entity exists' do
      before do
        allow(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_return(entity_response)
      end

      it 'returns the entity ID' do
        result = described_class.find_by_name(canonical_name)
        expect(result).to eq(entity_id)
      end

      it 'reads the legion- prefixed path' do
        expect(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_return(entity_response)

        described_class.find_by_name(canonical_name)
      end
    end

    context 'when entity does not exist (nil response)' do
      before do
        allow(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_return(nil)
      end

      it 'returns nil' do
        result = described_class.find_by_name(canonical_name)
        expect(result).to be_nil
      end
    end

    context 'when Vault raises HTTPClientError (404)' do
      before do
        allow(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_raise(Vault::HTTPClientError, 'entity not found')
      end

      it 'returns nil without raising' do
        result = described_class.find_by_name(canonical_name)
        expect(result).to be_nil
      end
    end

    context 'when Vault raises an unexpected StandardError' do
      before do
        allow(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_raise(StandardError, 'timeout')
      end

      it 'returns nil without raising' do
        result = described_class.find_by_name(canonical_name)
        expect(result).to be_nil
      end
    end

    context 'when response data has no id field' do
      before do
        allow(vault_logical).to receive(:read)
          .with("identity/entity/name/legion-#{canonical_name}")
          .and_return(double('Vault::Secret', data: { name: 'legion-foo' }))
      end

      it 'returns nil' do
        result = described_class.find_by_name(canonical_name)
        expect(result).to be_nil
      end
    end
  end

  # ---------------------------------------------------------------------------
  describe 'vault_logical resolution' do
    context 'when LeaseManager is defined' do
      it 'delegates to LeaseManager.instance.vault_logical' do
        expect(lease_manager).to receive(:vault_logical).and_return(vault_logical)
        allow(vault_logical).to receive(:read).and_return(nil)

        described_class.find_by_name(canonical_name)
      end
    end

    context 'when LeaseManager is not defined' do
      before do
        hide_const('Legion::Crypt::LeaseManager')

        stub_const('Vault', Module.new)
        stub_const('Vault::HTTPClientError', Class.new(StandardError))
        allow(Vault).to receive(:logical).and_return(vault_logical)
        allow(vault_logical).to receive(:read).and_return(nil)
      end

      it 'falls back to ::Vault.logical' do
        expect(Vault).to receive(:logical).and_return(vault_logical)

        described_class.find_by_name(canonical_name)
      end
    end
  end
end
