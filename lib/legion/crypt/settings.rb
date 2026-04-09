# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    module Settings
      extend Legion::Logging::Helper

      def self.tls
        {
          enabled: false,
          verify:  'peer',
          ca:      nil,
          cert:    nil,
          key:     nil
        }
      end

      def self.spiffe
        {
          enabled:             false,
          socket_path:         '/tmp/spire-agent/public/api.sock',
          trust_domain:        'legion.internal',
          workload_id:         nil,
          renewal_window:      0.5,
          allow_x509_fallback: false
        }
      end

      def self.default
        {
          vault:            vault,
          jwt:              jwt,
          tls:              tls,
          cs_encrypt_ready: false,
          dynamic_keys:     true,
          cluster_secret:   nil,
          save_private_key: true,
          read_private_key: true
        }
      end

      def self.jwt
        {
          enabled:           true,
          default_algorithm: 'HS256',
          default_ttl:       3600,
          issuer:            'legion',
          verify_expiration: true,
          verify_issuer:     true,
          jwks_tls_verify:   'peer'
        }
      end

      def self.vault
        {
          enabled:             !Gem::Specification.find_by_name('vault').nil?,
          protocol:            'http',
          address:             'localhost',
          port:                8200,
          token:               ENV['VAULT_DEV_ROOT_TOKEN_ID'] || ENV['VAULT_TOKEN_ID'] || nil,
          connected:           false,
          renewer_time:        5,
          renewer:             true,
          push_cluster_secret: false,
          read_cluster_secret: false,
          kv_path:             ENV['LEGION_VAULT_KV_PATH'] || 'legion',
          leases:              {},
          default:             nil,
          vault_namespace:     'legionio',
          kerberos:            {
            service_principal: nil,
            auth_path:         'auth/kerberos/login'
          },
          tls:                 {
            verify: 'peer'
          },
          clusters:            {},
          bootstrap_lease_ttl: 300,
          dynamic_rmq_creds:   false,
          dynamic_pg_creds:    false
        }
      end
    end
  end
end

begin
  if Legion.const_defined?('Settings')
    Legion::Settings.merge_settings('crypt', Legion::Crypt::Settings.default)
    Legion::Crypt::Settings.log.info('Legion::Crypt settings defaults merged')
  end
rescue StandardError => e
  if Legion::Crypt::Settings.respond_to?(:handle_exception)
    Legion::Crypt::Settings.handle_exception(e, level: :fatal, operation: 'crypt.settings.merge_defaults')
  else
    puts e.message
    puts e.backtrace
  end
end
