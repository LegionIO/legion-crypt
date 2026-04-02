# frozen_string_literal: true

require 'legion/logging/helper'

module Legion
  module Crypt
    module LdapAuth
      include Legion::Logging::Helper

      def ldap_login(cluster_name:, username:, password:)
        cluster_name = cluster_name.to_sym
        log.info "LDAP login requested user=#{username} cluster=#{cluster_name}"
        client = vault_client(cluster_name)
        secret = client.logical.write("auth/ldap/login/#{username}", password: password)
        auth = secret.auth
        token = auth.client_token

        clusters[cluster_name][:token] = token
        clusters[cluster_name][:connected] = true
        client.token = token if client.respond_to?(:token=)

        log.info "LDAP login success: user=#{username}, cluster=#{cluster_name}"
        { token: token, lease_duration: auth.lease_duration,
          renewable: auth.renewable?, policies: auth.policies }
      rescue StandardError => e
        handle_exception(e, level: :error, operation: 'crypt.ldap_auth.ldap_login', cluster_name: cluster_name, username: username)
        log.error "LDAP login failed: user=#{username}, cluster=#{cluster_name}: #{e.message}"
        raise
      end

      def ldap_login_all(username:, password:)
        results = {}
        clusters.each do |name, config|
          next unless config[:auth_method] == 'ldap'

          results[name] = ldap_login(cluster_name: name, username: username, password: password)
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.ldap_auth.ldap_login_all', cluster_name: name, username: username)
          log.warn("Legion::Crypt::LdapAuth#ldap_login_all cluster=#{name} failed: #{e.message}")
          results[name] = { error: e.message }
        end
        log.info "LDAP login_all complete successes=#{results.count { |_, result| result.is_a?(Hash) && !result.key?(:error) }} attempted=#{results.size}"
        results
      end
    end
  end
end
