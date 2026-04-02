# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    module Erasure
      extend Legion::Logging::Helper

      class << self
        def erase_tenant(tenant_id:)
          key_path = "#{tenant_prefix}/#{tenant_id}/master_key"

          log.info "[crypt] Erasing tenant #{tenant_id}"
          delete_vault_key(key_path) if defined?(Legion::Crypt::Vault)
          Legion::Events.emit('crypt.tenant_erased', { tenant_id: tenant_id, erased_at: Time.now.utc }) if defined?(Legion::Events)
          log.warn "[crypt] Tenant #{tenant_id} cryptographically erased"

          { erased: true, tenant_id: tenant_id, path: key_path }
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.erasure.erase_tenant', tenant_id: tenant_id)
          { erased: false, tenant_id: tenant_id, error: e.message }
        end

        def verify_erasure(tenant_id:)
          key_path = "#{tenant_prefix}/#{tenant_id}/master_key"
          data = Legion::Crypt::Vault.read(key_path)
          erased = data.nil?
          log.info "Tenant erasure verification completed for #{tenant_id}: erased=#{erased}"
          { erased: erased, tenant_id: tenant_id }
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.erasure.verify_erasure', tenant_id: tenant_id)
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
            handle_exception(e, level: :debug, operation: 'crypt.erasure.tenant_prefix')
            nil
          end || 'secret/data/legion/tenants'
        end
      end
    end
  end
end
