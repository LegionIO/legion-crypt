# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/mock_vault'

RSpec.describe Legion::Crypt::MockVault do
  before { described_class.reset! }

  describe 'read/write/delete' do
    it 'roundtrips data' do
      described_class.write('secret/test', { key: 'value' })
      expect(described_class.read('secret/test')).to eq({ key: 'value' })
    end

    it 'returns nil for missing path' do
      expect(described_class.read('nonexistent')).to be_nil
    end

    it 'deletes path' do
      described_class.write('secret/del', { a: 1 })
      described_class.delete('secret/del')
      expect(described_class.read('secret/del')).to be_nil
    end

    it 'returns independent copies' do
      original = { key: 'value' }
      described_class.write('secret/copy', original)
      result = described_class.read('secret/copy')
      result[:key] = 'modified'
      expect(described_class.read('secret/copy')).to eq({ key: 'value' })
    end
  end

  describe '.list' do
    it 'returns paths matching prefix' do
      described_class.write('secret/a/1', {})
      described_class.write('secret/a/2', {})
      described_class.write('secret/b/1', {})
      expect(described_class.list('secret/a/')).to contain_exactly('secret/a/1', 'secret/a/2')
    end
  end

  describe '.connected?' do
    it 'returns true' do
      expect(described_class.connected?).to be true
    end
  end
end
