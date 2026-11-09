# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/ed25519'
require 'legion/crypt/attestation'

RSpec.describe Legion::Crypt::Attestation do
  let(:keypair) { Legion::Crypt::Ed25519.generate_keypair }

  describe 'create and verify' do
    it 'roundtrips attestation' do
      att = described_class.create(
        agent_id: 'agent-1', capabilities: %w[read write],
        state: 'active', private_key: keypair[:private_key]
      )

      valid = described_class.verify(
        claim_hash:    att[:claim], signature_hex: att[:signature],
        public_key: keypair[:public_key]
      )
      expect(valid).to be true
    end

    it 'fails with tampered claim' do
      att = described_class.create(
        agent_id: 'agent-1', capabilities: %w[read],
        state: 'active', private_key: keypair[:private_key]
      )

      tampered = att[:claim].merge(agent_id: 'agent-evil')
      valid = described_class.verify(
        claim_hash:    tampered, signature_hex: att[:signature],
        public_key: keypair[:public_key]
      )
      expect(valid).to be false
    end
  end

  describe '.fresh?' do
    it 'returns true for recent claim' do
      claim = { timestamp: Time.now.utc.iso8601 }
      expect(described_class.fresh?(claim)).to be true
    end

    it 'returns false for old claim' do
      claim = { timestamp: (Time.now.utc - 600).iso8601 }
      expect(described_class.fresh?(claim, max_age_seconds: 300)).to be false
    end
  end
end
