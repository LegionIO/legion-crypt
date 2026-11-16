# frozen_string_literal: true

require 'singleton'
require 'legion/crypt/vault/leases'

module Legion
  module Crypt
    # The process-wide lease object. legion-settings (lease:// resolution) and legion-data (consumer
    # reconnects) call Legion::Crypt::LeaseManager.instance as a stable cross-gem contract, and it
    # must answer whether or not Vault is enabled, so it exists from load rather than per session.
    class LeaseManager < Legion::Crypt::Vault::Leases
      include Singleton
    end
  end
end
