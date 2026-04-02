# frozen_string_literal: true

require 'securerandom'
require 'legion/logging/helper'

module Legion
  module Crypt
    module Attestation
      extend Legion::Logging::Helper

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
          log.info "Attestation created for agent #{agent_id}, state=#{state}"

          { claim: claim, signature: signature.unpack1('H*'), payload: payload }
        rescue StandardError => e
          handle_exception(e, level: :error, operation: 'crypt.attestation.create', agent_id: agent_id, state: state)
          raise
        end

        def verify(claim_hash:, signature_hex:, public_key:)
          payload = Legion::JSON.dump(claim_hash)
          signature = [signature_hex].pack('H*')
          result = Legion::Crypt::Ed25519.verify(payload, signature, public_key)
          agent_id = claim_hash[:agent_id] || claim_hash['agent_id']
          if result
            log.info "Attestation verified for agent #{agent_id}"
          else
            log.warn "Attestation verification failed for agent #{agent_id}"
          end
          result
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.attestation.verify',
                              agent_id: claim_hash[:agent_id] || claim_hash['agent_id'])
          raise
        end

        def fresh?(claim_hash, max_age_seconds: 300)
          timestamp = Time.parse(claim_hash[:timestamp])
          Time.now.utc - timestamp < max_age_seconds
        rescue StandardError => e
          handle_exception(e, level: :warn, operation: 'crypt.attestation.fresh?',
                              agent_id: claim_hash[:agent_id] || claim_hash['agent_id'])
          false
        end
      end
    end
  end
end
