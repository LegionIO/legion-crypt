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

  before do
    Legion::Crypt.connect_vault
  end

  it '.write' do
    # expect { @vault.write('test', 'key', 'value') }.not_to raise_exception
  end

  it '.read' do
    # expect(@vault.read('creds/legion', 'rabbitmq')).to be_a Hash
  end

  it '.get' do
    # expect(@vault.get('test')).to be_a Hash
    # expect(@vault.get('test')).to eq({ key: 'value' })
  end

  it '.add_session' do
    expect(@vault.add_session(path: '/test')).to be_a Array
  end

  it 'exist?' do
    # expect(@vault.exist?('test')).to eq true
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
    # empty block
  end

  it '.renew_sessions' do
    expect(Legion::Crypt.renew_sessions).to eq []
  end
end
