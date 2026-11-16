# frozen_string_literal: true

module Legion
  module Crypt
    module Vault
      module Auth
        # JWT auth. Presents a signed JWT to Vault's JWT/OIDC method. Cannot re-authenticate on
        # its own — a fresh login with a new JWT is required once the token is unusable.
        class JWT
          include Legion::Crypt::Vault::Auth

          def can_reauth?
            false
          end

          # Issues a grant by presenting the given JWT to the configured role.
          def authenticate(client:, jwt:, **)
            jwt_config = cluster_config[:jwt]
            secret = client.logical.write(path: jwt_config[:auth_path], data: { role: jwt_config[:role], jwt: jwt })
            install_grant(secret)
          rescue Legion::Crypt::Vault::HTTPError => e
            raise AuthError, "Vault JWT auth failed: #{e.message}"
          end
        end
      end
    end
  end
end
