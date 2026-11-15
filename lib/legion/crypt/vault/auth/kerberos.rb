# frozen_string_literal: true

module Legion
  module Crypt
    module Vault
      module Auth
        # Kerberos (SPNEGO) auth. The SPNEGO token is sent as the HTTP Authorization header and
        # the client keeps its configured namespace. Can re-authenticate from the ticket cache.
        class Kerberos
          include Legion::Crypt::Vault::Auth

          class GemMissingError < AuthError; end

          def can_reauth?
            true
          end

          # Issues a grant from the current Kerberos ticket.
          def authenticate(client:, **)
            raise GemMissingError, 'lex-kerberos gem is required for Kerberos auth' unless spnego_available?

            kerberos = cluster_config[:kerberos]
            service_principal = kerberos[:service_principal]
            raise AuthError, 'Kerberos service_principal is not configured' unless service_principal

            spnego_token = obtain_spnego_token(service_principal: service_principal)
            data = client.put(path: kerberos[:auth_path], body: '{}',
                              headers: { 'Authorization' => "Negotiate #{spnego_token}" })
            install_grant(Legion::Crypt::Vault::Client::Secret.decode(data: data))
          rescue Legion::Crypt::Vault::HTTPError => e
            raise AuthError, "Vault Kerberos auth failed: #{e.message}"
          end

          # Re-authenticates from the ticket cache to produce a replacement grant.
          def reauth(client:, **)
            authenticate(client: client)
          end

          private

          def spnego_available?
            require 'legion/extensions/kerberos/helpers/spnego'
            true
          rescue LoadError => e
            handle_exception(e, level: :warn, operation: 'crypt.vault_auth_kerberos.spnego_available')
            defined?(Legion::Extensions::Kerberos::Helpers::Spnego) ? true : false
          end

          def obtain_spnego_token(service_principal:)
            helper = Object.new.extend(Legion::Extensions::Kerberos::Helpers::Spnego)
            result = helper.obtain_spnego_token(service_principal: service_principal)
            raise AuthError, "SPNEGO token acquisition failed: #{result[:error]}" unless result[:success]

            result[:token]
          end
        end
      end
    end
  end
end
