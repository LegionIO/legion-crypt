# frozen_string_literal: true

require 'spec_helper'

require 'legion/crypt/vault'

RSpec.describe Legion::Crypt::Vault do
  before do
    @vault = Class.new
    @vault.extend Legion::Crypt::Vault
    @vault.sessions = []
  end

  it('.settings') { expect(@vault.settings).to be_a Hash }

  it '.connect_vault' do
    expect { @vault.connect_vault }.not_to raise_exception
  end

  describe '#connect_vault rescue logging' do
    before do
      # Ensure a token is present so connect_vault reaches ::Vault.sys.health_status
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]).and_call_original
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]).with(:token).and_return('test-token')
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]=)
      allow(Vault).to receive(:address=)
      allow(Vault).to receive(:token=)
      allow(Vault.sys).to receive(:health_status).and_raise(StandardError, 'connection refused')
    end

    it 'returns false and does not raise when Vault.sys.health_status raises' do
      expect(@vault.connect_vault).to eq false
    end

    it 'logs via log_exception when available' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(true)
      expect(logging).to receive(:log_exception).with(instance_of(StandardError), lex: 'crypt', component_type: :helper)
      @vault.connect_vault
    end

    it 'falls back to Logging.error with backtrace when log_exception unavailable' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(false)
      allow(logging).to receive(:respond_to?).with(:error).and_return(true)
      expect(logging).to receive(:error).with(match(/connection refused/))
      @vault.connect_vault
    end

    it 'does not raise and returns false when Legion::Logging is absent' do
      hide_const('Legion::Logging')
      allow(Kernel).to receive(:warn)
      result = nil
      expect { result = @vault.connect_vault }.not_to raise_error
      expect(result).to eq false
    end
  end

  before do
    Legion::Crypt.connect_vault
  end

  it '.write' do
    # TODO: requires live Vault connectivity (::Vault.kv#write) - skipped in unit tests
  end

  it '.read' do
    # TODO: requires live Vault connectivity (::Vault.logical#read) - skipped in unit tests
  end

  it '.get' do
    # TODO: requires live Vault connectivity (::Vault.kv#read) - skipped in unit tests
  end

  it '.add_session' do
    expect(@vault.add_session(path: '/test')).to be_a Array
  end

  it 'exist?' do
    # TODO: requires live Vault connectivity (::Vault.kv#read_metadata) - skipped in unit tests
  end

  it '.close_sessions' do
    expect(@vault.close_sessions).to be_a Array
  end

  it '.shutdown_renewer' do
    expect(@vault.shutdown_renewer).to eq nil
  end

  it '.close_session' do
    expect(Legion::Crypt.close_sessions).to be_a Array
  end

  it '.renew_session' do
    # TODO: requires live Vault connectivity (::Vault.sys#renew) - skipped in unit tests
  end

  it '.renew_sessions' do
    expect(Legion::Crypt.renew_sessions).to eq []
  end
end
