# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'legion/crypt/version'
require 'legion/crypt/settings'
require 'legion/crypt/cipher'

module Legion
  module Crypt
    class << self
      attr_reader :sessions

      include Legion::Crypt::Cipher

      unless Gem::Specification.find_by_name('vault').nil?
        require 'legion/crypt/vault'
        include Legion::Crypt::Vault
      end

      def start
        Legion::Logging.debug 'Legion::Crypt is running start'
        ::File.write('./legionio.key', private_key) if settings[:save_private_key]

        connect_vault unless settings[:vault][:token].nil?
      end

      def settings
        if Legion.const_defined?('Settings')
          Legion::Settings[:crypt]
        else
          Legion::Crypt::Settings.default
        end
      end

      def shutdown
        shutdown_renewer
        close_sessions
      end
    end
  end
end
