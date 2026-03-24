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

  before do
    stub_const('Legion::Settings', Module.new)
    allow(Legion::Settings).to receive(:[]).with(:security).and_return(
      { mtls: { enabled: false, vault_pki_path: 'pki/issue/legion-internal', cert_ttl: '24h' } }
    )
  end

  describe '.enabled?' do
    it 'returns false when security.mtls.enabled is false' do
      expect(described_class.enabled?).to be false
    end

    it 'returns true when security.mtls.enabled is true' do
      allow(Legion::Settings).to receive(:[]).with(:security).and_return(
        { mtls: { enabled: true, vault_pki_path: 'pki/issue/legion-internal', cert_ttl: '24h' } }
      )
      expect(described_class.enabled?).to be true
    end

    it 'returns false when security settings are missing' do
      allow(Legion::Settings).to receive(:[]).with(:security).and_return(nil)
      expect(described_class.enabled?).to be false
    end
  end

  describe '.pki_path' do
    it 'reads from settings' do
      expect(described_class.pki_path).to eq 'pki/issue/legion-internal'
    end

    it 'defaults to pki/issue/legion-internal when setting is nil' do
      allow(Legion::Settings).to receive(:[]).with(:security).and_return({ mtls: {} })
      expect(described_class.pki_path).to eq 'pki/issue/legion-internal'
    end

    it 'returns default when security is nil' do
      allow(Legion::Settings).to receive(:[]).with(:security).and_return(nil)
      expect(described_class.pki_path).to eq 'pki/issue/legion-internal'
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
    before do
      vault_logical = double('VaultLogical')
      stub_const('Vault', Module.new)
      allow(Vault).to receive(:logical).and_return(vault_logical)
      allow(vault_logical).to receive(:write).and_return(vault_response)
    end

    it 'calls Vault.logical.write with pki path and common_name' do
      expect(::Vault.logical).to receive(:write).with(
        'pki/issue/legion-internal',
        hash_including(common_name: 'node.legion.internal', ttl: '24h')
      ).and_return(vault_response)
      described_class.issue_cert(common_name: 'node.legion.internal')
    end

    it 'returns a hash with cert, key, ca_chain, serial, expiry' do
      result = described_class.issue_cert(common_name: 'node.legion.internal')
      expect(result).to include(:cert, :key, :ca_chain, :serial, :expiry)
    end

    it 'returns cert as a string' do
      result = described_class.issue_cert(common_name: 'node.legion.internal')
      expect(result[:cert]).to include('BEGIN CERTIFICATE')
    end

    it 'returns key as a string' do
      result = described_class.issue_cert(common_name: 'node.legion.internal')
      expect(result[:key]).to include('BEGIN RSA PRIVATE KEY')
    end

    it 'returns expiry as a Time' do
      result = described_class.issue_cert(common_name: 'node.legion.internal')
      expect(result[:expiry]).to be_a(Time)
    end

    it 'accepts a custom ttl override' do
      expect(::Vault.logical).to receive(:write).with(
        anything,
        hash_including(ttl: '4h')
      ).and_return(vault_response)
      described_class.issue_cert(common_name: 'node.legion.internal', ttl: '4h')
    end

    it 'includes ip_sans with local IP' do
      ip = described_class.local_ip
      expect(::Vault.logical).to receive(:write).with(
        anything,
        hash_including(ip_sans: ip)
      ).and_return(vault_response)
      described_class.issue_cert(common_name: 'node.legion.internal')
    end

    it 'raises when Vault returns nil' do
      allow(::Vault.logical).to receive(:write).and_return(nil)
      expect { described_class.issue_cert(common_name: 'x') }.to raise_error(RuntimeError, /Vault PKI returned nil/)
    end
  end
end
