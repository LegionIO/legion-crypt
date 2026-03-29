# frozen_string_literal: true

module Legion
  module Crypt
    module Settings
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
          enabled:        false,
          socket_path:    '/tmp/spire-agent/public/api.sock',
          trust_domain:   'legion.internal',
          workload_id:    nil,
          renewal_window: 0.5
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
          verify_issuer:     true
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
          push_cluster_secret: true,
          read_cluster_secret: true,
          kv_path:             ENV['LEGION_VAULT_KV_PATH'] || 'legion',
          leases:              {},
          default:             nil,
          vault_namespace:     'legionio',
          kerberos:            {
            service_principal: nil,
            auth_path:         'auth/kerberos/login'
          },
          clusters:            {}
        }
      end
    end
  end
end

begin
  Legion::Settings.merge_settings('crypt', Legion::Crypt::Settings.default) if Legion.const_defined?('Settings')
rescue StandardError => e
  if Legion.const_defined?('Logging') && Legion::Logging.respond_to?(:log_exception)
    Legion::Logging.log_exception(e, lex: 'crypt', component_type: :helper, level: :fatal)
  elsif Legion.const_defined?('Logging') && Legion::Logging.respond_to?(:fatal)
    Legion::Logging.fatal("crypt settings merge error: #{e.class}: #{e.message}\n#{Array(e.backtrace).join("\n")}")
  else
    puts e.message
    puts e.backtrace
  end
end
