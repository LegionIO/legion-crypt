# frozen_string_literal: true

require 'securerandom'

module Legion
  module Crypt
    module Attestation
      class << self
        def create(agent_id:, capabilities:, state:, private_key:)
          claim = {
            agent_id:     agent_id,
            capabilities: Array(capabilities),
            state:        state.to_s,
            timestamp:    Time.now.utc.iso8601,
            nonce:        SecureRandom.hex(16)
          }

          payload = Legion::JSON.dump(claim)
          signature = Legion::Crypt::Ed25519.sign(payload, private_key)

          { claim: claim, signature: signature.unpack1('H*'), payload: payload }
        end

        def verify(claim_hash:, signature_hex:, public_key:)
          payload = Legion::JSON.dump(claim_hash)
          signature = [signature_hex].pack('H*')
          Legion::Crypt::Ed25519.verify(payload, signature, public_key)
        end

        def fresh?(claim_hash, max_age_seconds: 300)
          timestamp = Time.parse(claim_hash[:timestamp])
          Time.now.utc - timestamp < max_age_seconds
        rescue StandardError
          false
        end
      end
    end
  end
end
