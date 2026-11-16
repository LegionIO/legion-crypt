# frozen_string_literal: true

module Legion
  module Crypt
    module Vault
      module Auth
        # LDAP auth. Requires explicit username/password and cannot re-authenticate on its own —
        # a fresh login is required once the token is unusable.
        class LDAP
          include Legion::Crypt::Vault::Auth

          def can_reauth?
            false
          end

          # Issues a grant with the given credentials.
          def authenticate(client:, username:, password:, **)
            raise ArgumentError, 'LDAP username must be a single path segment' if username.include?('/')

            secret = client.logical.write(path: "#{cluster_config[:ldap][:auth_path]}/#{username}", data: { password: password })
            install_grant(secret)
          rescue Legion::Crypt::Vault::HTTPError => e
            raise AuthError, "Vault LDAP auth failed: #{e.message}"
          end
        end
      end
    end
  end
end
