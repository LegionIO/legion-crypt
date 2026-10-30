# frozen_string_literal: true

require 'legion/logging/helper'
require 'legion/crypt/vault_operation'

module Legion
  module Crypt
    module LdapAuth
      include Legion::Logging::Helper

      def ldap_login(cluster_name:, username:, password:)
        cluster_name = cluster_name.to_sym
        generation = lifecycle_mutex.synchronize do
          raise 'Crypt is shutting down; LDAP login must be retried' if @stopping

          @token_generation || 0
        end
        log.info "LDAP login requested user=#{username} cluster=#{cluster_name}"
        client = vault_client(cluster_name)
        secret = Legion::Crypt::VaultOperation.with_timeout do
          client.logical.write(path: "auth/ldap/login/#{username}", data: { password: password })
        end
        auth = secret.auth
        token = auth.client_token

        ttl = auth.lease_duration.to_f
        expires_at = ttl.positive? ? Time.now + ttl : nil
        lifecycle_mutex.synchronize do
          raise 'Crypt stopped during LDAP login; login must be retried' if @stopping || generation != (@token_generation || 0)

          previous = (@token_renewers || []).find { |worker| worker.cluster_name == cluster_name }
          previous&.stop
          raise 'Previous LDAP token worker has not stopped; login must be retried' if previous&.running?

          config = clusters.fetch(cluster_name)
          publish_vault_token(client: client, config: config, token: token)
          config[:lease_duration] = auth.lease_duration
          config[:renewable] = auth.renewable?
          config[:expires_at] = expires_at
          config[:connected] = expires_at.nil? || expires_at > Time.now
          config[:relogin_required] = !config[:connected]
          start_token_renewer(cluster_name: cluster_name, config: config, vault_client: client)
        end

        log.info "LDAP login success: user=#{username}, cluster=#{cluster_name}"
        { token: token, lease_duration: auth.lease_duration,
          renewable: auth.renewable?, policies: auth.policies }
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
