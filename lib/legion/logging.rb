# frozen_string_literal: true

require 'logger'

begin
  gem_root = Gem::Specification.find_by_name('legion-logging').full_gem_path
  upstream_logging = File.join(gem_root, 'lib/legion/logging.rb')
  require upstream_logging if File.exist?(upstream_logging)
rescue Gem::LoadError
  nil
end

module Legion
  module Logging
    class << self
      unless method_defined?(:setup)
        def setup(level: 'info', **_opts)
          logger.level = normalize_level(level)
          self
        end

        def logger
          @logger ||= Logger.new($stdout).tap do |instance|
            instance.progname = 'legion-crypt'
          end
        end

        def log_exception(exception, lex: nil, component_type: nil, **_opts)
          prefix = [lex, component_type].compact.join('.')
          payload = prefix.empty? ? exception.message : "#{prefix}: #{exception.message}"
          error(payload)
        end

        %i[debug info warn error fatal unknown].each do |level_name|
          define_method(level_name) do |message = nil, &block|
            payload = block ? block.call : message
            return if payload.nil?

            logger.public_send(level_name, payload)
          end
        end

        private

        def normalize_level(level)
          case level.to_s.downcase
          when 'debug' then Logger::DEBUG
          when 'info' then Logger::INFO
          when 'warn' then Logger::WARN
          when 'error' then Logger::ERROR
          when 'fatal' then Logger::FATAL
          else Logger::UNKNOWN
          end
        end
      end
    end
  end
end
