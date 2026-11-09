# frozen_string_literal: true

require 'spec_helper'

require 'legion/crypt/version'

RSpec.describe Legion::Crypt do
  it 'has a version number' do
    expect(Legion::Crypt::VERSION).not_to be nil
    expect(Legion::Crypt::VERSION).to be_a String
  end
end
