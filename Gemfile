# frozen_string_literal: true

source 'https://rubygems.org'

gemspec
group :test do
  gem 'rake'
  gem 'rspec'
  gem 'rspec_junit_formatter'
  gem 'rubocop'
  gem 'rubocop-legion'
  gem 'simplecov'
end
gem 'legion-logging'
companion_root = File.directory?(File.expand_path('.ci-dependencies', __dir__)) ? '.ci-dependencies' : '..'
settings_path = File.expand_path("#{companion_root}/legion-settings", __dir__)
gem 'legion-settings', **(File.directory?(settings_path) ? { path: settings_path } : {})
