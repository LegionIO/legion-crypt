# frozen_string_literal: true

module Legion
  module Crypt
    module MockVault
      @store = {}
      @mutex = Mutex.new

      class << self
        def read(path)
          @mutex.synchronize { @store[path]&.dup }
        end

        def write(path, data)
          @mutex.synchronize { @store[path] = data.dup }
          true
        end

        def delete(path)
          @mutex.synchronize { @store.delete(path) }
          true
        end

        def list(prefix)
          @mutex.synchronize do
            @store.keys.select { |k| k.start_with?(prefix) }
          end
        end

        def reset!
          @mutex.synchronize { @store.clear }
        end

        def connected?
          true
        end
      end
    end
  end
end
