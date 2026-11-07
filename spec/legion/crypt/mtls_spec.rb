# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/mtls'

RSpec.describe Legion::Crypt::Mtls do
  let(:vault_response) do
    double(
      'VaultResponse',
      data: {
        certificate:   "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
        private_key:   "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
        ca_chain:      ["-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"],
        serial_number: '01:02:03:04',
        expiration:    (Time.now + 86_400).to_i
      }
    )
  end

  around do |example|
    original = Legion::Settings[:crypt]
    Legion::Settings.set_prop(:crypt, Legion::Crypt::Settings.default)
    example.run
  ensure
    Legion::Settings.set_prop(:crypt, original)
  end

  describe 'live security policy' do
    it 'honors explicit disabled policy after replacing the settings tree' do
      Legion::Settings.set_prop(:crypt, Legion::Crypt::Settings.default.merge(mtls: { enabled: true }))
      expect(described_class.enabled?).to be(true)
      Legion::Settings.set_prop(:crypt, Legion::Crypt::Settings.default.merge(mtls: { enabled: false }))
      expect(described_class.enabled?).to be(false)
    end
  end

  describe '.local_ip' do
    it 'uses loopback when interface discovery fails operationally' do
      allow(Socket).to receive(:ip_address_list).and_raise(Errno::ENETDOWN)

      expect(described_class.local_ip).to eq('127.0.0.1')
    end

    it 'propagates programming errors instead of issuing certificates for loopback' do
      failure = NoMethodError.new('invalid interface discovery call')
      allow(Socket).to receive(:ip_address_list).and_raise(failure)

      expect { described_class.local_ip }.to(raise_error { |error| expect(error).to equal(failure) })
    end
  end

  describe '.issue_cert' do
    let(:vault_logical) { instance_double(Legion::Crypt::VaultClient::Logical) }

    before do
      allow(Legion::Crypt).to receive(:vault_client).and_return(double('core Vault client', logical: vault_logical))
      allow(vault_logical).to receive(:write).and_return(vault_response)
    end

    it 'returns expiry as a Time' do
      result = described_class.issue_cert(common_name: 'node.legion.internal')
      expect(result[:expiry]).to be_a(Time)
    end

    it 'accepts a custom ttl override' do
      expect(vault_logical).to receive(:write).with(
        path: anything,
        data: hash_including(ttl: '4h')
      ).and_return(vault_response)
      described_class.issue_cert(common_name: 'node.legion.internal', ttl: '4h')
    end

    it 'includes ip_sans with local IP' do
      ip = described_class.local_ip
      expect(vault_logical).to receive(:write).with(
        path: anything,
        data: hash_including(ip_sans: ip)
      ).and_return(vault_response)
      described_class.issue_cert(common_name: 'node.legion.internal')
    end

    it 'preserves Vault issuance failures' do
      failure = RuntimeError.new('issuance unavailable')
      allow(vault_logical).to receive(:write).and_raise(failure)
      expect { described_class.issue_cert(common_name: 'x') }.to(raise_error { |error| expect(error).to equal(failure) })
    end
  end
end
