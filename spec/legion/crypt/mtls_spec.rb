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
    original = Legion::Settings[:security]
    Legion::Settings.set_prop(:security, { mtls: { enabled: false, vault_pki_path: 'pki/issue/legion-internal', cert_ttl: '24h' } })
    example.run
  ensure
    Legion::Settings.set_prop(:security, original)
  end

  describe 'live security policy' do
    it 'honors explicit disabled policy after replacing the settings tree' do
      Legion::Settings.set_prop(:security, { mtls: { enabled: true } })
      expect(described_class.enabled?).to be(true)
      Legion::Settings.set_prop(:security, { mtls: { enabled: false } })
      expect(described_class.enabled?).to be(false)
    end
  end

  describe '.local_ip' do
    it 'returns a string' do
      expect(described_class.local_ip).to be_a(String)
    end

    it 'returns a non-empty address' do
      expect(described_class.local_ip).not_to be_empty
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
