# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/erasure'
require 'legion/crypt/vault_client'

RSpec.describe Legion::Crypt::Erasure do
  before do
    stub_const('Legion::Events', Module.new)
    allow(Legion::Events).to receive(:emit)
  end

  describe '.erase_tenant' do
    it 'returns success when vault delete succeeds' do
      expect(Legion::Crypt).to receive(:delete).with('secret/data/legion/tenants/tenant-123/master_key').and_return(success: true)

      result = described_class.erase_tenant(tenant_id: 'tenant-123')
      expect(result[:erased]).to be true
      expect(result[:tenant_id]).to eq('tenant-123')
      expect(Legion::Events).to have_received(:emit).with('crypt.tenant_erased', hash_including(tenant_id: 'tenant-123'))
    end

    it 'returns failure on error' do
      allow(Legion::Crypt).to receive(:delete).and_raise(StandardError.new('vault unreachable'))
      expect(Legion::Events).not_to receive(:emit)

      result = described_class.erase_tenant(tenant_id: 'tenant-123')
      expect(result[:erased]).to be false
      expect(result[:error]).to include('vault unreachable')
    end

    it 'fails closed when deletion is forbidden' do
      allow(Legion::Crypt).to receive(:delete).and_return(success: false, error: 'Vault HTTP 403: permission denied')
      expect(Legion::Events).not_to receive(:emit)

      result = described_class.erase_tenant(tenant_id: 'tenant-123')

      expect(result).to include(erased: false, tenant_id: 'tenant-123')
      expect(result[:error]).to include('permission denied')
    end
  end

  describe '.verify_erasure' do
    it 'returns erased=true when the key is absent' do
      allow(Legion::Crypt).to receive(:read).and_return(nil)

      result = described_class.verify_erasure(tenant_id: 'tenant-123')

      expect(result).to include(erased: true, tenant_id: 'tenant-123')
    end

    it 'returns erased=false when the key still exists' do
      allow(Legion::Crypt).to receive(:read).and_return(private_key: 'present')

      result = described_class.verify_erasure(tenant_id: 'tenant-123')

      expect(result).to include(erased: false, tenant_id: 'tenant-123')
    end

    it 'fails closed when Vault access raises' do
      allow(Legion::Crypt).to receive(:read).and_raise(StandardError, 'vault unreachable')

      result = described_class.verify_erasure(tenant_id: 'tenant-123')

      expect(result).to include(erased: false, tenant_id: 'tenant-123')
      expect(result[:error]).to include('vault unreachable')
    end

    it 'does not treat an unreadable key as erased' do
      error = Legion::Crypt::Vault::HTTPClientError.new(code: 403, errors: ['permission denied'])
      allow(Legion::Crypt).to receive(:read).and_raise(error)

      result = described_class.verify_erasure(tenant_id: 'tenant-123')

      expect(result).to include(erased: false, tenant_id: 'tenant-123')
      expect(result[:error]).to include('permission denied')
    end
  end
end
