# frozen_string_literal: true

begin
  helper_path = File.join(
    Gem::Specification.find_by_name('legion-logging').full_gem_path,
    'lib/legion/logging/helper.rb'
  )
  require helper_path if File.exist?(helper_path)
rescue Gem::LoadError
  nil
end

require 'legion/logging'

module Legion
  module Logging
    module Helper
      unless method_defined?(:handle_exception) || private_method_defined?(:handle_exception)
        unless const_defined?(:CompatLogger, false)
          CompatLogger = Class.new do
            %i[debug info warn error fatal unknown].each do |level|
              define_method(level) do |message = nil, &block|
                payload = block ? block.call : message
                return if payload.nil?

                if Legion.const_defined?('Logging') && Legion::Logging.respond_to?(level)
                  Legion::Logging.public_send(level, payload)
                elsif %i[error fatal warn].include?(level)
                  ::Kernel.warn(payload)
                else
                  $stdout.puts(payload)
                end
              end
            end
          end
        end

        def log
          @log ||= CompatLogger.new
        end

        def handle_exception(exception, task_id: nil, level: :error, handled: true, **opts) # rubocop:disable Lint/UnusedMethodArgument,Style/ArgumentsForwarding
          message = exception_log_message(exception, level: level, **opts) # rubocop:disable Style/ArgumentsForwarding

          if Legion.const_defined?('Logging')
            if Legion::Logging.respond_to?(:log_exception)
              Legion::Logging.log_exception(exception, lex: 'crypt', component_type: :helper)
              return
            end
            if Legion::Logging.respond_to?(level)
              Legion::Logging.public_send(level, message)
              return
            end
            if Legion::Logging.respond_to?(:error)
              Legion::Logging.error(message)
              return
            end
            if Legion::Logging.respond_to?(:warn)
              Legion::Logging.warn(message)
              return
            end
          end

          ::Kernel.warn(message)
        end

        private

        def exception_log_message(exception, level:, **opts)
          operation = opts[:operation] || opts['operation']
          prefix = operation ? "#{operation} failed: " : ''
          details = opts.reject { |key, _value| key.to_s == 'operation' }.map { |key, value| "#{key}=#{value}" }
          detail_suffix = details.empty? ? '' : " (#{details.join(' ')})"
          backtrace = Array(exception.backtrace).first(10).join("\n")
          base = "#{prefix}#{exception.class}: #{exception.message}#{detail_suffix}"
          return base if backtrace.empty? && level == :debug
          return base if backtrace.empty?

          "#{base}\n#{backtrace}"
        end
      end
    end
  end
end
