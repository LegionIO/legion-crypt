# frozen_string_literal: true

require 'singleton'

module Legion
  module Crypt
    # Compatibility facade. legion-settings (lease:// reference resolution) and legion-data
    # (consumer reconnects) call Legion::Crypt::LeaseManager.instance as a stable cross-gem
    # contract. The real lease state now lives in the default cluster's Vault::Leases; every
    # method here delegates to it. Do not add real state to this class.
    class LeaseManager
      include Singleton

      def fetch(name, key)
        leases&.fetch(name, key)
      end

      def lease_data(name)
        leases&.lease_data(name)
      end

      def active_leases
        leases&.active_leases || {}
      end

      def fetched_count
        leases&.fetched_count
      end

      def reissue_lease(name, **)
        leases&.reissue_lease(name)
      end

      def update_settings_refs(settings:, publish: nil, &)
        leases&.update_settings_refs(settings: settings, publish: publish, &)
      end

      private

      def leases
        sessions = Legion::Crypt.respond_to?(:vault_sessions) ? Legion::Crypt.vault_sessions : nil
        return nil if sessions.nil?

        sessions[Legion::Crypt.default_cluster_name]&.leases
      end
    end
  end
end
