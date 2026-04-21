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
      unless const_defined?(:CompatLogger, false)
        CompatLogger = Class.new do
          %i[debug info warn error fatal unknown].each do |level|
            define_method(level) do |message = nil, &block|
              payload = block ? block.call : message
              return if payload.nil?

              if logging_supports?(level)
                Legion::Logging.public_send(level, payload)
              elsif %i[error fatal warn].include?(level)
                ::Kernel.warn(payload)
              else
                $stdout.puts(payload)
              end
            end
          end

          private

          def logging_supports?(level)
            return false unless Legion.const_defined?('Logging')

            Legion::Logging.respond_to?(level)
          rescue StandardError
            false
          end
        end
      end

      def log
        @log ||= CompatLogger.new
      end

      def handle_exception(exception, task_id: nil, level: :error, handled: true, **opts) # rubocop:disable Lint/UnusedMethodArgument,Style/ArgumentsForwarding
        message = exception_log_message(exception, level: level, **opts) # rubocop:disable Style/ArgumentsForwarding

        if logging_supports?(:log_exception)
          Legion::Logging.log_exception(exception, level: level, lex: 'crypt', component_type: :helper)
          return
        end
        if logging_supports?(level)
          Legion::Logging.public_send(level, message)
          return
        end
        if logging_supports?(:error)
          Legion::Logging.error(message)
          return
        end
        if logging_supports?(:warn)
          Legion::Logging.warn(message)
          return
        end

        ::Kernel.warn(message)
      end

      private

      def logging_supports?(level)
        return false unless Legion.const_defined?('Logging')

        Legion::Logging.respond_to?(level)
      rescue StandardError
        false
      end

      def exception_log_message(exception, level:, **opts)
        operation = opts[:operation] || opts['operation']
        prefix = operation ? "#{operation} failed: " : ''
        details = opts.reject { |key, _value| key.to_s == 'operation' }.map { |key, value| "#{key}=#{value}" }
        detail_suffix = details.empty? ? '' : " (#{details.join(' ')})"
        backtrace = Array(exception.backtrace).first(10).join("\n")
        base = "#{prefix}#{exception.class}: #{exception.message}#{detail_suffix}"
        return base if backtrace.empty? || level == :debug
        return base if backtrace.empty?

        "#{base}\n#{backtrace}"
      end
    end
  end
end
