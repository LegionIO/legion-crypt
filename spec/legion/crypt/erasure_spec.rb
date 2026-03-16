# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/erasure'

RSpec.describe Legion::Crypt::Erasure do
  describe '.erase_tenant' do
    it 'returns success when vault delete succeeds' do
      allow(described_class).to receive(:delete_vault_key)

      result = described_class.erase_tenant(tenant_id: 'tenant-123')
      expect(result[:erased]).to be true
      expect(result[:tenant_id]).to eq('tenant-123')
    end

    it 'returns failure on error' do
      allow(described_class).to receive(:delete_vault_key).and_raise(StandardError.new('vault unreachable'))

      result = described_class.erase_tenant(tenant_id: 'tenant-123')
      expect(result[:erased]).to be false
      expect(result[:error]).to include('vault unreachable')
    end
  end
end
