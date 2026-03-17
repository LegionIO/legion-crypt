# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/tls'

RSpec.describe Legion::Crypt::TLS do
  describe '.enabled?' do
    it 'defaults to false' do
      expect(described_class.enabled?).to be_falsey
    end
  end

  describe '.bunny_options' do
    it 'returns empty hash when disabled' do
      allow(described_class).to receive(:enabled?).and_return(false)
      expect(described_class.bunny_options).to eq({})
    end

    it 'returns tls options when enabled' do
      allow(described_class).to receive(:enabled?).and_return(true)
      opts = described_class.bunny_options
      expect(opts[:tls]).to be true
      expect(opts[:verify_peer]).to be true
    end
  end

  describe '.sequel_options' do
    it 'returns empty hash when disabled' do
      allow(described_class).to receive(:enabled?).and_return(false)
      expect(described_class.sequel_options).to eq({})
    end

    it 'returns ssl options when enabled' do
      allow(described_class).to receive(:enabled?).and_return(true)
      opts = described_class.sequel_options
      expect(opts[:sslmode]).to eq('verify-full')
    end
  end

  describe '.cert_path' do
    it 'has default path' do
      expect(described_class.cert_path).to include('legion.crt')
    end
  end

  describe '.key_path' do
    it 'has default path' do
      expect(described_class.key_path).to include('legion.key')
    end
  end

  describe '.ca_path' do
    it 'has default path' do
      expect(described_class.ca_path).to include('ca-bundle.crt')
    end
  end

  describe '.ssl_context' do
    it 'returns an SSL context' do
      ctx = described_class.ssl_context
      expect(ctx).to be_a(OpenSSL::SSL::SSLContext)
      expect(ctx.verify_mode).to eq(OpenSSL::SSL::VERIFY_PEER)
    end
  end
end
