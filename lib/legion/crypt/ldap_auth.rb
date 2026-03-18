# frozen_string_literal: true

module Legion
  module Crypt
    module LdapAuth
      def ldap_login(cluster_name:, username:, password:)
        cluster_name = cluster_name.to_sym
        client = vault_client(cluster_name)
        secret = client.logical.write("auth/ldap/login/#{username}", password: password)
        auth = secret.auth
        token = auth.client_token

        clusters[cluster_name][:token] = token
        clusters[cluster_name][:connected] = true

        { token: token, lease_duration: auth.lease_duration,
          renewable: auth.renewable, policies: auth.policies }
      end

      def ldap_login_all(username:, password:)
        results = {}
        clusters.each do |name, config|
          next unless config[:auth_method] == 'ldap'

          results[name] = ldap_login(cluster_name: name, username: username, password: password)
        rescue StandardError => e
          results[name] = { error: e.message }
        end
        results
      end
    end
  end
end
