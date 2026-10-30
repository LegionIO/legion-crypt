# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/vault_operation'

module Legion
  module Crypt
    module LdapAuth
      include Legion::Logging::Helper

      def ldap_login(cluster_name:, username:, password:)
        cluster_name = cluster_name.to_sym
        generation = vault_auth_generation
        config = clusters.fetch(cluster_name)
        log.info "LDAP login requested user=#{username} cluster=#{cluster_name}"
        client = vault_client(cluster_name)
        secret = Legion::Crypt::VaultOperation.with_timeout do
          client.logical.write(path: "auth/ldap/login/#{username}", data: { password: password })
        end
        auth = secret.auth

        grant = { token: auth.client_token, lease_duration: auth.lease_duration, renewable: auth.renewable?, policies: auth.policies }
        install_vault_grant(client: client, config: config, grant: grant, auth_method: 'ldap', generation: generation)

        log.info "LDAP login success: user=#{username}, cluster=#{cluster_name}"
        grant
      rescue StandardError => e
        log.error "LDAP login failed: user=#{username}, cluster=#{cluster_name}, error=#{e.class}"
        raise
      end

      def ldap_login_all(username:, password:)
        results = {}
        clusters.each do |name, config|
          next unless config[:auth_method].to_s == 'ldap'

          results[name] = ldap_login(cluster_name: name, username: username, password: password)
        rescue StandardError => e
          log.warn("Legion::Crypt::LdapAuth#ldap_login_all cluster=#{name} failed: #{e.class}")
          message = password.to_s.empty? ? e.message : e.message.gsub(password.to_s, '[REDACTED]')
          results[name] = { error: message }
        end
        log.info "LDAP login_all complete successes=#{results.count { |_, result| result.is_a?(Hash) && !result.key?(:error) }} attempted=#{results.size}"
        results
      end
    end
  end
end
