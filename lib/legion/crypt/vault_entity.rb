# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    module VaultEntity
      extend Legion::Logging::Helper

      # Create or lookup a Vault entity for a Legion principal.
      # Returns the Vault entity ID string, or nil on failure.
      def self.ensure_entity(principal_id:, canonical_name:, metadata: {})
        existing = find_by_name(canonical_name)
        return existing if existing

        response = vault_logical.write(
          'identity/entity',
          name:     "legion-#{canonical_name}",
          metadata: metadata.merge(
            legion_principal_id:   principal_id,
            legion_canonical_name: canonical_name,
            managed_by:            'legion'
          )
        )
        extract_id(response)
      rescue ::Vault::HTTPClientError => e
        log.warn "Vault entity creation failed (#{canonical_name}): #{e.message}"
        nil
      rescue StandardError => e
        log.warn "Vault entity creation unexpected error (#{canonical_name}): #{e.message}"
        nil
      end

      # Create an alias linking an auth method mount to the entity.
      # Idempotent — swallows "already exists" 4xx errors.
      def self.ensure_alias(entity_id:, mount_accessor:, alias_name:)
        vault_logical.write(
          'identity/entity-alias',
          name:           alias_name,
          canonical_id:   entity_id,
          mount_accessor: mount_accessor
        )
      rescue ::Vault::HTTPClientError => e
        raise unless e.message.include?('already exists')

        log.debug 'Vault entity alias already exists (idempotent)'
        nil
      rescue StandardError => e
        log.warn "Vault entity alias creation unexpected error (#{alias_name}): #{e.message}"
        nil
      end

      # Look up a Vault entity by its Legion canonical name.
      # Returns the Vault entity ID string, or nil if not found.
      def self.find_by_name(canonical_name)
        response = vault_logical.read("identity/entity/name/legion-#{canonical_name}")
        extract_id(response)
      rescue ::Vault::HTTPClientError => e
        # Re-log non-404 client errors as warnings before swallowing
        log.warn "Vault entity lookup client error (#{canonical_name}): #{e.message}" unless e.message.match?(/not found|does not exist|404/i)
        nil
      rescue StandardError => e
        log.warn "Vault entity lookup failed (#{canonical_name}): #{e.message}"
        nil
      end

      # ---------------------------------------------------------------------------
      # Private helpers
      # ---------------------------------------------------------------------------

      def self.vault_logical
        if defined?(Legion::Crypt::LeaseManager)
          Legion::Crypt::LeaseManager.instance.vault_logical
        else
          ::Vault.logical
        end
      end
      private_class_method :vault_logical

      # Extract entity ID from a Vault response, supporting both symbol and
      # string keys (Vault SDK may return either depending on version/transport).
      def self.extract_id(response)
        data = response&.data
        return nil unless data

        data[:id] || data['id']
      end
      private_class_method :extract_id
    end
  end
end
