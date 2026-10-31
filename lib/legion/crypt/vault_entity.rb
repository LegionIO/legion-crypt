# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/vault_client'
require 'legion/crypt/lease_manager'

module Legion
  module Crypt
    module VaultEntity
      extend Legion::Logging::Helper

      # Create or lookup a Vault entity for a Legion principal.
      # Returns the Vault entity ID string, or nil on failure.
      def self.ensure_entity(principal_id:, canonical_name:, metadata: {})
        existing = find_by_name(canonical_name: canonical_name)
        return existing if existing

        response = Legion::Crypt::LeaseManager.instance.vault_logical.write(
          path: 'identity/entity',
          data: {
            name:     "legion-#{canonical_name}",
            metadata: metadata.merge(
              legion_principal_id:   principal_id,
              legion_canonical_name: canonical_name,
              managed_by:            'legion'
            )
          }
        )
        extract_id(response)
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.vault_entity.ensure_entity', canonical_name: canonical_name)
        nil
      end

      # Create an alias linking an auth method mount to the entity.
      # Idempotent — swallows "already exists" 4xx errors.
      def self.ensure_alias(entity_id:, mount_accessor:, alias_name:)
        Legion::Crypt::LeaseManager.instance.vault_logical.write(
          path: 'identity/entity-alias',
          data: { name: alias_name, canonical_id: entity_id, mount_accessor: mount_accessor }
        )
      rescue Legion::Crypt::Vault::HTTPClientError => e
        if e.message.include?('already exists')
          log.debug 'Vault entity alias already exists (idempotent)'
        else
          handle_exception(e, level: :warn, operation: 'crypt.vault_entity.ensure_alias', alias_name: alias_name)
        end
        nil
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.vault_entity.ensure_alias', alias_name: alias_name)
        nil
      end

      # Look up a Vault entity by its Legion canonical name.
      # Returns the Vault entity ID string, or nil if not found.
      def self.find_by_name(canonical_name:)
        response = Legion::Crypt::LeaseManager.instance.vault_logical.read(path: "identity/entity/name/legion-#{canonical_name}")
        extract_id(response)
      rescue StandardError => e
        handle_exception(e, level: :warn, operation: 'crypt.vault_entity.find_by_name', canonical_name: canonical_name)
        nil
      end

      # ---------------------------------------------------------------------------
      # Private helpers
      # ---------------------------------------------------------------------------

      # Extract the entity ID from the client's symbol-keyed response data.
      def self.extract_id(response)
        data = response&.data
        return nil unless data

        data[:id]
      end
      private_class_method :extract_id
    end
  end
end
