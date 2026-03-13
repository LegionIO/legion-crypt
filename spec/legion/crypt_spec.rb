# frozen_string_literal: true

require 'spec_helper'

require 'legion/crypt'
# require 'legion/transport'
# Legion::Transport::Connection.setup

RSpec.describe Legion::Crypt do
  it 'has a version number' do
    expect(Legion::Crypt::VERSION).not_to be nil
  end

  it 'can start' do
    expect { Legion::Crypt.start }.not_to raise_exception
  end

  it 'can stop' do
    expect { Legion::Crypt.shutdown }.not_to raise_exception
  end
end
