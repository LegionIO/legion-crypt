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

  describe '.store_keypair and .load_private_key' do
    let(:keypair) { described_class.generate_keypair }

    it 'stores keypairs via Legion::Crypt.write' do
      allow(Legion::Crypt).to receive(:write)

      described_class.store_keypair(agent_id: 'agent-1', keypair: keypair)

      expect(Legion::Crypt).to have_received(:write).with(
        'keys/agent-1',
        private_key: keypair[:private_key].unpack1('H*'),
        public_key:  keypair[:public_key_hex]
      )
    end

    it 'loads private keys via Legion::Crypt.get' do
      allow(Legion::Crypt).to receive(:get).with('keys/agent-1')
                          .and_return(private_key: keypair[:private_key].unpack1('H*'))

      result = described_class.load_private_key(agent_id: 'agent-1')

      expect(result).to eq(keypair[:private_key])
    end
  end
end
