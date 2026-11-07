# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/settings'

module Legion
  module Crypt
    module Erasure
      extend Legion::Logging::Helper

      class << self
        def erase_tenant(tenant_id:)
          key_path = "#{Legion::Settings[:crypt][:partition_keys][:vault_tenant_prefix]}/#{tenant_id}/master_key"

          log.info "[crypt] Erasing tenant #{tenant_id}"
          result = Legion::Crypt.delete(key_path)
          raise(result[:error] || 'Vault key deletion failed') unless result[:success]

          Legion::Events.emit('crypt.tenant_erased', { tenant_id: tenant_id, erased_at: Time.now.utc }) if defined?(Legion::Events)
          log.warn "[crypt] Tenant #{tenant_id} cryptographically erased"

          { erased: true, tenant_id: tenant_id, path: key_path }
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.erasure.erase_tenant', tenant_id: tenant_id)
          { erased: false, tenant_id: tenant_id, error: e.message }
        end

        def verify_erasure(tenant_id:)
          key_path = "#{Legion::Settings[:crypt][:partition_keys][:vault_tenant_prefix]}/#{tenant_id}/master_key"

          data = Legion::Crypt.read(key_path, nil)
          erased = data.nil?
          log.info "Tenant erasure verification completed for #{tenant_id}: erased=#{erased}"
          { erased: erased, tenant_id: tenant_id }
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.erasure.verify_erasure', tenant_id: tenant_id)
          { erased: false, tenant_id: tenant_id, error: e.message }
        end
      end
    end
  end
end
