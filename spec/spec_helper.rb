# frozen_string_literal: true

begin
  require 'simplecov'
  SimpleCov.start do
    merging true
  end
rescue LoadError
  puts 'Failed to load file for coverage reports, continuing without it'
end

require 'bundler/setup'
lib_path = File.expand_path('../lib', __dir__)
$LOAD_PATH.delete(lib_path)
$LOAD_PATH.unshift(lib_path)
require 'legion/logging'
require 'legion/settings'
require 'legion/settings/resolver'

Legion::Logging.setup(level: 'fatal')
Legion::Settings.load
Legion::Settings[:transport][:connection] = { vhost: '/' }

require 'legion/crypt'

RSpec.configure do |config|
  config.example_status_persistence_file_path = '.rspec_status'
  config.disable_monkey_patching!
  config.around do |example|
    settings = Legion::Settings.loader.settings
    original = settings.dup
    settings.replace(Marshal.load(Marshal.dump(original)))
    Legion::Settings.set_prop(:crypt, Legion::Crypt::Settings.default)
    example.run
  ensure
    Legion::Settings.loader.settings.replace(original)
  end

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
