# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/vault/client'
require 'legion/crypt/vault/operation'

module Legion
  module Crypt
    module Vault
      # Shared login behavior for a Vault auth method, mixed into the concrete
      # Vault::Auth::Kerberos / LDAP / JWT classes. Reads this cluster's config live from
      # Legion::Settings with bracket access; the token's lifecycle belongs to Vault::Session.
      module Auth
        include Legion::Logging::Helper

        class AuthError < StandardError; end

        # The login auth response. The session holds the live grant and renews it; this is the
        # strategy's own record of what it last issued.
        attr_reader :grant

        def initialize(cluster_name:, **)
          @cluster_name = cluster_name
          @grant = nil
        end

        private

        # The effective config for this cluster: the named cluster's settings, or the top-level
        # vault settings for the single-cluster (nil) case. A named cluster that is not
        # configured is a configuration error, not a fallback.
        def cluster_config
          vault = Legion::Settings[:crypt][:vault]
          @cluster_name ? vault[:clusters].fetch(@cluster_name) : vault
        end

        # Validates a login secret and installs its auth response as the current grant.
        def install_grant(secret)
          raise AuthError, 'Vault auth returned no auth data' unless secret&.auth

          @grant = secret.auth
        end
      end
    end
  end
end

require 'legion/crypt/vault/auth/kerberos'
require 'legion/crypt/vault/auth/ldap'
require 'legion/crypt/vault/auth/jwt'
