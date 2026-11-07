# frozen_string_literal: true

require 'timeout'
require 'legion/crypt/settings'

module Legion
  module Crypt
    module VaultOperation
      DEFAULT_TIMEOUT = 5
      SHUTDOWN_TIMEOUT = 10

      def self.with_timeout(deadline: nil, **)
        timeout = Legion::Settings[:crypt][:vault][:operation_timeout]
        raise ArgumentError, 'Vault operation_timeout must be a finite positive number' unless timeout.is_a?(Numeric) && timeout.finite? && timeout.positive?

        if deadline
          remaining = deadline - ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
          raise Timeout::Error, 'Vault operation deadline expired' unless remaining.positive?

          timeout = [timeout, remaining].min
        end
        operation_deadline = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) + timeout
        Timeout.timeout(timeout) { yield(operation_deadline) }
      end
    end
  end
end
