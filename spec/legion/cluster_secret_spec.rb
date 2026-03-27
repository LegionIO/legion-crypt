# frozen_string_literal: true

require 'spec_helper'

require 'legion/crypt/cluster_secret'

RSpec.describe Legion::Crypt::ClusterSecret do
  before do
    @cs = Class.new
    @cs.extend Legion::Crypt::ClusterSecret

    @vault_mock = Module.new do
      def self.get(_)
        { cluster_secret: SecureRandom.hex(32) }
      end
    end

    @original_cluster_secret = Legion::Settings[:crypt][:cluster_secret]
  end

  after do
    Legion::Settings[:crypt][:cluster_secret] = @original_cluster_secret
  end

  it '.find_cluster_secret' do
    expect(@cs.find_cluster_secret).not_to be_nil
  end

  it 'can from_vault without Vault being loaded' do
    expect(@cs.from_vault).to be_nil
  end

  # it '.from_settings' do
  #   expect(@cs.from_settings).to be_nil
  # end

  it '.force_cluster_secret' do
    expect(@cs.force_cluster_secret).to eq true
  end

  it '.settings_push_vault' do
    expect(@cs.settings_push_vault).to eq true
  end

  it '.only_member?' do
    expect(@cs.only_member?).to eq nil
  end

  it '.push_cs_to_vault' do
    expect(@cs.push_cs_to_vault).to eq false
  end

  it '.cluster_secret_timeout' do
    expect(@cs.cluster_secret_timeout).to eq 5
  end

  it '.secret_length' do
    expect(@cs.secret_length).to eq 32
  end

  it '.generate_secure_random' do
    expect(@cs.generate_secure_random).to be_a String
  end

  it '.validate_hex' do
    expect(@cs.validate_hex(@cs.find_cluster_secret)).to be_truthy
  end

  it 'complains when it doesn\'t find a valid hex' do
    Legion::Settings[:crypt][:cluster_secret] = 'not valid'
    expect(@cs.validate_hex(Legion::Settings[:crypt][:cluster_secret])).to be_falsey
    expect(@cs.find_cluster_secret).not_to eq 'not valid'
    expect(@cs.validate_hex(@cs.cluster_secret)).to be_truthy
  end

  it 'can do magic things with vault(fake)' do
    expect(@cs.from_vault).to be_nil
  end

  describe '#from_transport rescue paths' do
    before do
      # Simulate transport connected but require itself raising an error
      allow(Legion::Settings[:transport]).to receive(:[]).and_call_original
      allow(Legion::Settings[:transport]).to receive(:[]).with(:connected).and_return(true)
      allow(@cs).to receive(:require).and_raise(StandardError, 'transport error')
    end

    it 'returns nil when an exception is raised' do
      expect(@cs.from_transport).to be_nil
    end

    it 'logs via log_exception when available' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(true)
      expect(logging).to receive(:log_exception).with(instance_of(StandardError), lex: 'crypt', component_type: :helper)
      @cs.from_transport
    end

    it 'falls back to Logging.error with backtrace when log_exception unavailable' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(false)
      allow(logging).to receive(:respond_to?).with(:error).and_return(true)
      expect(logging).to receive(:error).with(match(/transport error/))
      @cs.from_transport
    end

    it 'does not raise and returns nil when Legion::Logging is absent' do
      hide_const('Legion::Logging')
      expect { @cs.from_transport }.not_to raise_error
      expect(@cs.from_transport).to be_nil
    end
  end

  describe '#cs rescue paths' do
    before do
      allow(@cs).to receive(:find_cluster_secret).and_raise(StandardError, 'digest error')
    end

    it 'returns nil when find_cluster_secret raises' do
      expect(@cs.cs).to be_nil
    end

    it 'logs via log_exception when available' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(true)
      expect(logging).to receive(:log_exception).with(instance_of(StandardError), lex: 'crypt', component_type: :helper)
      @cs.cs
    end

    it 'falls back to Logging.error with backtrace when log_exception unavailable' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(false)
      allow(logging).to receive(:respond_to?).with(:error).and_return(true)
      expect(logging).to receive(:error).with(match(/digest error/))
      @cs.cs
    end

    it 'falls back to Logging.warn when only warn is available' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(false)
      allow(logging).to receive(:respond_to?).with(:error).and_return(false)
      allow(logging).to receive(:respond_to?).with(:warn).and_return(true)
      expect(logging).to receive(:warn).with(match(/digest error/))
      @cs.cs
    end

    it 'returns nil without raising when Legion::Logging is absent' do
      hide_const('Legion::Logging')
      expect { @cs.cs }.not_to raise_error
      expect(@cs.cs).to be_nil
    end
  end
end
