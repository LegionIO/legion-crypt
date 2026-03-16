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

  describe 'LeaseManager integration' do
    before do
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:start_renewal_thread)
      allow(Legion::Crypt::LeaseManager.instance).to receive(:shutdown)
    end

    it 'starts LeaseManager when vault is connected and leases are defined' do
      Legion::Settings[:crypt][:vault][:connected] = true
      Legion::Settings[:crypt][:vault][:leases] = { 'test' => { 'path' => 'secret/test' } }
      Legion::Crypt.start
      expect(Legion::Crypt::LeaseManager.instance).to have_received(:start)
    ensure
      Legion::Settings[:crypt][:vault][:connected] = false
      Legion::Settings[:crypt][:vault][:leases] = {}
    end

    it 'does not start LeaseManager when no leases are defined' do
      Legion::Settings[:crypt][:vault][:leases] = {}
      Legion::Crypt.start
      expect(Legion::Crypt::LeaseManager.instance).not_to have_received(:start)
    end

    it 'does not start LeaseManager when vault is not connected' do
      Legion::Settings[:crypt][:vault][:connected] = false
      Legion::Settings[:crypt][:vault][:leases] = { 'test' => { 'path' => 'secret/test' } }
      Legion::Crypt.start
      expect(Legion::Crypt::LeaseManager.instance).not_to have_received(:start)
    ensure
      Legion::Settings[:crypt][:vault][:leases] = {}
    end

    it 'shuts down LeaseManager during shutdown' do
      Legion::Crypt.shutdown
      expect(Legion::Crypt::LeaseManager.instance).to have_received(:shutdown)
    end
  end
end
