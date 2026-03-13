# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/settings'

RSpec.describe Legion::Crypt::Settings do
  it 'has default settings' do
    expect(Legion::Crypt::Settings.default[:vault]).to be_a Hash
    expect(Legion::Crypt::Settings.default[:cs_encrypt_ready]).to eq false
    expect(Legion::Crypt::Settings.default[:dynamic_keys]).to eq true
    expect(Legion::Crypt::Settings.default[:vault][:protocol]).to eq 'http'
    expect(Legion::Crypt::Settings.default[:vault][:address]).to eq 'localhost'
    expect(Legion::Crypt::Settings.vault).to be_a Hash
  end
end
