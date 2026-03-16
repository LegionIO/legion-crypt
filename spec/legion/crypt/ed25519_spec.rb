# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/ed25519'

RSpec.describe Legion::Crypt::Ed25519 do
  describe '.generate_keypair' do
    it 'returns private and public keys' do
      kp = described_class.generate_keypair
      expect(kp[:private_key]).to be_a(String)
      expect(kp[:public_key]).to be_a(String)
      expect(kp[:public_key_hex]).to match(/\A[a-f0-9]{64}\z/)
    end
  end

  describe '.sign and .verify' do
    let(:keypair) { described_class.generate_keypair }

    it 'roundtrips sign/verify' do
      sig = described_class.sign('hello', keypair[:private_key])
      expect(described_class.verify('hello', sig, keypair[:public_key])).to be true
    end

    it 'fails verify with wrong key' do
      other = described_class.generate_keypair
      sig = described_class.sign('hello', keypair[:private_key])
      expect(described_class.verify('hello', sig, other[:public_key])).to be false
    end

    it 'fails verify with tampered message' do
      sig = described_class.sign('hello', keypair[:private_key])
      expect(described_class.verify('tampered', sig, keypair[:public_key])).to be false
    end
  end
end
