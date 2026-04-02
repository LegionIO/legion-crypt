# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/erasure'

RSpec.describe Legion::Crypt::Erasure do
  describe '.erase_tenant' do
    it 'returns success when vault delete succeeds' do
      allow(Legion::Crypt).to receive(:delete)

      result = described_class.erase_tenant(tenant_id: 'tenant-123')
      expect(result[:erased]).to be true
      expect(result[:tenant_id]).to eq('tenant-123')
    end

    it 'returns failure on error' do
      allow(Legion::Crypt).to receive(:delete).and_raise(StandardError.new('vault unreachable'))

      result = described_class.erase_tenant(tenant_id: 'tenant-123')
      expect(result[:erased]).to be false
      expect(result[:error]).to include('vault unreachable')
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
  end
end
