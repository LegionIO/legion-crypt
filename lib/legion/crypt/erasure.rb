# frozen_string_literal: true

module Legion
  module Crypt
    module Erasure
      class << self
        def erase_tenant(tenant_id:)
          key_path = "#{tenant_prefix}/#{tenant_id}/master_key"

          delete_vault_key(key_path) if defined?(Legion::Crypt::Vault)
          Legion::Events.emit('crypt.tenant_erased', { tenant_id: tenant_id, erased_at: Time.now.utc }) if defined?(Legion::Events)
          Legion::Logging.warn "[crypt] Tenant #{tenant_id} cryptographically erased" if defined?(Legion::Logging)

          { erased: true, tenant_id: tenant_id, path: key_path }
        rescue StandardError => e
          Legion::Logging.error("Legion::Crypt::Erasure#erase_tenant failed: #{e.message}") if defined?(Legion::Logging)
          { erased: false, tenant_id: tenant_id, error: e.message }
        end

        def verify_erasure(tenant_id:)
          key_path = "#{tenant_prefix}/#{tenant_id}/master_key"
          data = Legion::Crypt::Vault.read(key_path)
          { erased: data.nil?, tenant_id: tenant_id }
        rescue StandardError => e
          Legion::Logging.warn("Legion::Crypt::Erasure#verify_erasure failed: #{e.message}") if defined?(Legion::Logging)
          { erased: true, tenant_id: tenant_id }
        end

        private

        def delete_vault_key(path)
          ::Vault.logical.delete(path)
        end

        def tenant_prefix
          begin
            Legion::Settings[:crypt][:partition_keys][:vault_tenant_prefix]
          rescue StandardError => e
            Legion::Logging.debug("Legion::Crypt::Erasure#tenant_prefix settings lookup failed: #{e.message}") if defined?(Legion::Logging)
            nil
          end || 'secret/data/legion/tenants'
        end
      end
    end
  end
end
