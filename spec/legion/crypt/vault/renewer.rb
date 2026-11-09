# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'rbconfig'

RSpec.describe 'Legion::Crypt::Vault::Renewer' do
  let(:result) do
    probe = File.expand_path('../../../support/vault_renewer_probe.rb', __dir__)
    root = File.expand_path('../../../..', __dir__)
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-Ilib', probe, scenario, chdir: root)
    raise "Renewal scenario failed: #{stderr}" unless status.success?

    line = stdout.lines.find { |entry| entry.start_with?('RENEWER_RESULT=') }
    Legion::JSON.load(line.delete_prefix('RENEWER_RESULT='))
  end

  context 'during periodic renewal' do
    let(:scenario) { 'renew' }

    it 'renews both tracked sessions through the real actor and Vault client' do
      expect(result[:requests]).to eq([
                                        { method: 'PUT', path: '/v1/sys/leases/renew', lease_id: 'lease/first' },
                                        { method: 'PUT', path: '/v1/sys/leases/renew', lease_id: 'lease/second' }
                                      ])
      expect(result[:sessions]).to eq(%w[lease/first lease/second])
    end
  end

  context 'when cancelled before its first tick' do
    let(:scenario) { 'cancel' }

    it 'stops its scheduler without discarding sessions owned by Crypt' do
      expect(result[:terminated]).to be(true)
      expect(result[:running]).to be(false)
      expect(result[:requests]).to eq([])
      expect(result[:sessions]).to eq(%w[lease/first lease/second])
    end
  end
end
