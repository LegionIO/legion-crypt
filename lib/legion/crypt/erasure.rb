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
          if Legion::Crypt.respond_to?(:delete)
            Legion::Crypt.delete(key_path)
          elsif defined?(Legion::Crypt::Vault)
            delete_vault_key(key_path)
          end
          Legion::Events.emit('crypt.tenant_erased', { tenant_id: tenant_id, erased_at: Time.now.utc }) if defined?(Legion::Events)
          log.warn "[crypt] Tenant #{tenant_id} cryptographically erased"

          { erased: true, tenant_id: tenant_id, path: key_path }
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.erasure.erase_tenant', tenant_id: tenant_id)
          { erased: false, tenant_id: tenant_id, error: e.message }
        end

        def verify_erasure(tenant_id:)
          key_path = "#{tenant_prefix}/#{tenant_id}/master_key"
          raise 'Legion::Crypt.read is unavailable' unless Legion::Crypt.respond_to?(:read)

          data = Legion::Crypt.read(key_path, nil)
          erased = data.nil?
          log.info "Tenant erasure verification completed for #{tenant_id}: erased=#{erased}"
          { erased: erased, tenant_id: tenant_id }
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.erasure.verify_erasure', tenant_id: tenant_id)
          { erased: false, tenant_id: tenant_id, error: e.message }
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
