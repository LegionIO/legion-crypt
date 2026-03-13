# frozen_string_literal: true

module Legion
  module Crypt
    module Settings
      def self.default
        {
          vault:            vault,
          cs_encrypt_ready: false,
          dynamic_keys:     true,
          cluster_secret:   nil,
          save_private_key: true,
          read_private_key: true
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
          kv_path:             ENV['LEGION_VAULT_KV_PATH'] || 'legion'
        }
      end
    end
  end
end

begin
  Legion::Settings.merge_settings('crypt', Legion::Crypt::Settings.default) if Legion.const_defined?('Settings')
rescue StandardError => e
  if Legion.const_defined?('Logging') && Legion::Logging.method_defined?(:fatal)
    Legion::Logging.fatal(e.message)
    Legion::Logging.fatal(e.backtrace)
  else
    puts e.message
    puts e.backtrace
  end
end
