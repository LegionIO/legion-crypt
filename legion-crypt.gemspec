# frozen_string_literal: true

require_relative 'lib/legion/crypt/version'

Gem::Specification.new do |spec|
  spec.name = 'legion-crypt'
  spec.version       = Legion::Crypt::VERSION
  spec.authors       = ['Esity']
  spec.email         = ['matthewdiverson@gmail.com']
  spec.summary       = 'Handles requests for encrypt, decrypting, connecting to Vault, among other things'
  spec.description   = 'A gem used by the LegionIO framework for encryption'
  spec.homepage      = 'https://github.com/LegionIO/legion-crypt'
  spec.license       = 'Apache-2.0'
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 3.4'
  spec.files = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.extra_rdoc_files = %w[README.md LICENSE CHANGELOG.md]
  spec.metadata = {
    'bug_tracker_uri'       => 'https://github.com/LegionIO/legion-crypt/issues',
    'changelog_uri'         => 'https://github.com/LegionIO/legion-crypt/blob/main/CHANGELOG.md',
    'documentation_uri'     => 'https://github.com/LegionIO/legion-crypt',
    'homepage_uri'          => 'https://github.com/LegionIO/LegionIO',
    'source_code_uri'       => 'https://github.com/LegionIO/legion-crypt',
    'wiki_uri'              => 'https://github.com/LegionIO/legion-crypt/wiki',
    'rubygems_mfa_required' => 'true'
  }

  spec.add_dependency 'vault', '>= 0.17'

  spec.add_development_dependency 'legion-logging'
  spec.add_development_dependency 'legion-settings'
end
