# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/partition_keys'

RSpec.describe Legion::Crypt::PartitionKeys do
  let(:master_key) { OpenSSL::Random.random_bytes(32) }

  describe '.derive_key' do
    it 'returns 32-byte key' do
      key = described_class.derive_key(master_key: master_key, tenant_id: 'tenant-1')
      expect(key.bytesize).to eq(32)
    end

    it 'is deterministic for same inputs' do
      k1 = described_class.derive_key(master_key: master_key, tenant_id: 'tenant-1')
      k2 = described_class.derive_key(master_key: master_key, tenant_id: 'tenant-1')
      expect(k1).to eq(k2)
    end

    it 'differs by tenant_id' do
      k1 = described_class.derive_key(master_key: master_key, tenant_id: 'tenant-1')
      k2 = described_class.derive_key(master_key: master_key, tenant_id: 'tenant-2')
      expect(k1).not_to eq(k2)
    end
  end

  describe 'encrypt/decrypt roundtrip' do
    it 'recovers plaintext' do
      encrypted = described_class.encrypt_for_tenant(plaintext: 'secret data', tenant_id: 'tenant-1', master_key: master_key)
      plaintext = described_class.decrypt_for_tenant(
        ciphertext:  encrypted[:ciphertext],
        init_vector: encrypted[:iv],
        auth_tag:    encrypted[:auth_tag],
        tenant_id:   'tenant-1',
        master_key:  master_key
      )
      expect(plaintext).to eq('secret data')
    end

    it 'fails with wrong tenant_id' do
      encrypted = described_class.encrypt_for_tenant(plaintext: 'secret', tenant_id: 'tenant-1', master_key: master_key)
      expect do
        described_class.decrypt_for_tenant(
          ciphertext: encrypted[:ciphertext], init_vector: encrypted[:iv], auth_tag: encrypted[:auth_tag],
          tenant_id: 'tenant-2', master_key: master_key
        )
      end.to raise_error(OpenSSL::Cipher::CipherError)
    end
  end
end
