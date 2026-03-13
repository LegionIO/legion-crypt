# frozen_string_literal: true

begin
  require 'simplecov'
  SimpleCov.start do
    use_merging true
    add_filter '/spec/'
    formatter SimpleCov::Formatter::Codecov if ENV.key?('CODECOV_TOKEN')
    formatter SimpleCov::Formatter::SimpleFormatter if ENV.key? 'SONAR_TOKEN'
  end
rescue LoadError
  puts 'Failed to load file for coverage reports, continuing without it'
end

require 'bundler/setup'
require 'legion/logging'
require 'legion/settings'

Legion::Logging.setup(level: 'fatal')
Legion::Settings.load
Legion::Settings[:transport][:connection] = { vhost: '/' }

require 'legion/crypt'

RSpec.configure do |config|
  config.example_status_persistence_file_path = '.rspec_status'
  config.disable_monkey_patching!
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
