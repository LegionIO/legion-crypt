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

  describe '.verify_external_token' do
    it 'delegates to JWT.verify_with_jwks' do
      expect(Legion::Crypt::JWT).to receive(:verify_with_jwks)
        .with('token', jwks_url: 'https://example.com/keys', issuers: ['iss'])
        .and_return({ sub: 'test' })

      result = Legion::Crypt.verify_external_token(
        'token', jwks_url: 'https://example.com/keys', issuers: ['iss']
      )
      expect(result[:sub]).to eq('test')
    end
  end

  describe 'multi-cluster module methods' do
    it 'responds to :cluster' do
      expect(Legion::Crypt).to respond_to(:cluster)
    end

    it 'responds to :clusters' do
      expect(Legion::Crypt).to respond_to(:clusters)
    end

    it 'responds to :vault_client' do
      expect(Legion::Crypt).to respond_to(:vault_client)
    end

    it 'responds to :ldap_login_all' do
      expect(Legion::Crypt).to respond_to(:ldap_login_all)
    end

    it ':clusters returns a hash' do
      expect(Legion::Crypt.clusters).to be_a(Hash)
    end
  end

  describe '.delete' do
    context 'when Vault is available' do
      let(:logical) { double('logical') }

      before do
        allow(Vault).to receive(:logical).and_return(logical)
        allow(logical).to receive(:delete).and_return(true)
      end

      it 'deletes the Vault path' do
        result = Legion::Crypt.delete('secret/data/legion/workers/w-1/entra')
        expect(logical).to have_received(:delete).with('secret/data/legion/workers/w-1/entra')
        expect(result).to include(success: true)
      end
    end

    context 'when Vault is not available' do
      before do
        allow(Vault).to receive(:logical).and_raise(StandardError, 'not connected')
      end

      it 'returns failure without raising' do
        result = Legion::Crypt.delete('secret/data/legion/workers/w-1/entra')
        expect(result[:success]).to be false
      end
    end
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
