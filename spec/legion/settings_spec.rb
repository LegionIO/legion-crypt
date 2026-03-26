# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/settings'

RSpec.describe Legion::Crypt::Settings do
  describe '.default' do
    subject(:defaults) { described_class.default }

    it 'returns a hash' do
      expect(defaults).to be_a(Hash)
    end

    it 'has vault settings as a hash' do
      expect(defaults[:vault]).to be_a(Hash)
    end

    it 'has cs_encrypt_ready set to false' do
      expect(defaults[:cs_encrypt_ready]).to eq(false)
    end

    it 'has dynamic_keys set to true' do
      expect(defaults[:dynamic_keys]).to eq(true)
    end

    it 'has cluster_secret as nil' do
      expect(defaults[:cluster_secret]).to be_nil
    end

    it 'has save_private_key' do
      expect(defaults).to have_key(:save_private_key)
    end

    it 'has read_private_key' do
      expect(defaults).to have_key(:read_private_key)
    end
  end

  describe '.vault' do
    subject(:vault) { described_class.vault }

    it 'returns a hash' do
      expect(vault).to be_a(Hash)
    end

    it 'defaults protocol to http' do
      expect(vault[:protocol]).to eq('http')
    end

    it 'defaults address to localhost' do
      expect(vault[:address]).to eq('localhost')
    end

    it 'defaults port to 8200' do
      expect(vault[:port]).to eq(8200)
    end

    it 'defaults connected to false' do
      expect(vault[:connected]).to eq(false)
    end

    it 'has renewer_time of 5' do
      expect(vault[:renewer_time]).to eq(5)
    end

    it 'has renewer enabled' do
      expect(vault[:renewer]).to eq(true)
    end

    it 'has push_cluster_secret enabled' do
      expect(vault[:push_cluster_secret]).to eq(true)
    end

    it 'has read_cluster_secret enabled' do
      expect(vault[:read_cluster_secret]).to eq(true)
    end

    it 'has kv_path' do
      expect(vault[:kv_path]).to be_a(String)
    end

    it 'reads VAULT_DEV_ROOT_TOKEN_ID from env' do
      original = ENV.fetch('VAULT_DEV_ROOT_TOKEN_ID', nil)
      ENV['VAULT_DEV_ROOT_TOKEN_ID'] = 'dev-test-token'
      expect(described_class.vault[:token]).to eq('dev-test-token')
      ENV['VAULT_DEV_ROOT_TOKEN_ID'] = original
    end

    it 'falls back to VAULT_TOKEN_ID env' do
      original_dev = ENV.delete('VAULT_DEV_ROOT_TOKEN_ID')
      original = ENV.fetch('VAULT_TOKEN_ID', nil)
      ENV['VAULT_TOKEN_ID'] = 'fallback-token'
      expect(described_class.vault[:token]).to eq('fallback-token')
      ENV['VAULT_TOKEN_ID'] = original
      ENV['VAULT_DEV_ROOT_TOKEN_ID'] = original_dev if original_dev
    end

    it 'reads LEGION_VAULT_KV_PATH from env' do
      original = ENV.fetch('LEGION_VAULT_KV_PATH', nil)
      ENV['LEGION_VAULT_KV_PATH'] = 'custom/path'
      expect(described_class.vault[:kv_path]).to eq('custom/path')
      ENV['LEGION_VAULT_KV_PATH'] = original
    end

    it 'has leases as an empty hash' do
      expect(vault[:leases]).to eq({})
    end

    it 'has default as nil' do
      expect(vault[:default]).to be_nil
    end

    it 'has clusters as an empty hash' do
      expect(vault[:clusters]).to eq({})
    end

    it 'includes kerberos defaults' do
      expect(vault[:kerberos]).to eq(
        service_principal: nil,
        auth_path:         'auth/kerberos/login'
      )
    end

    it 'defaults vault_namespace to legionio' do
      expect(vault[:vault_namespace]).to eq('legionio')
    end
  end
end
