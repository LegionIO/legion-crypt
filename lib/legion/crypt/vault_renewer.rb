# frozen_string_literal: true

require 'legion/extensions/actors/every'

module Legion
  module Crypt
    module Vault
      class Renewer < Legion::Extensions::Actors::Every
        def runner_function
          'renew_sessions'
        end

        def runner_class
          Legion::Crypt
        end

        def time
          5
        end

        def check_subtask?
          false
        end

        def generate_task?
          false
        end

        def use_runner?
          false
        end
      end
    end
  end
end
