# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/cluster_secret'

RSpec.describe Legion::Crypt::ClusterSecret do
  let(:configuration) { Legion::Crypt::Settings.default }
  let(:transport) { { connected: false, enabled: false } }
  let(:client) { { shutting_down: false } }
  let(:initialization_error) { described_class::InitializationError }

  before do
    @cs = Class.new.extend(described_class)
    stub_const('Legion::Transport::Queue', Class.new)
    stub_const('Legion::Transport::Messages::RequestClusterSecret', Class.new)
    allow(Legion::Transport::Queue).to receive(:new).with('node.crypt', passive: true)
                                                    .and_return(double(consumer_count: 1))
    allow(@cs).to receive(:require).with('legion/transport/messages/request_cluster_secret').and_return(true)
    allow(Legion::Settings).to receive(:[]).and_call_original
    allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)
    allow(Legion::Settings).to receive(:[]).with(:transport).and_return(transport)
    allow(Legion::Settings).to receive(:[]).with(:client).and_return(client)
  end

  it 'bootstraps a validated key when transport is explicitly disabled' do
    secret = @cs.find_cluster_secret
    expect(@cs.validate_hex(secret)).to be(true)
    expect(@cs.cs).to eq(Digest::SHA256.digest(secret))
  end

  [false, nil].each do |membership|
    it "does not generate a competing secret when membership is #{membership.inspect}" do
      allow(@cs).to receive(:only_member?).and_return(membership)
      expect(@cs).not_to receive(:generate_secure_random)
      expect { @cs.cs }.to raise_error(initialization_error)
      expect(configuration[:cs_encrypt_ready]).to be(false)
    end
  end

  it 'bootstraps an empty cluster within the deadline without waiting for a nonexistent peer' do
    transport[:connected] = true
    configuration[:cluster_secret_timeout] = 0.05
    request = double('cluster secret request')
    allow(Legion::Transport::Messages::RequestClusterSecret).to receive(:new).and_return(request)
    allow(request).to receive(:publish) { sleep(1) }
    allow(Legion::Transport::Queue).to receive(:new).with('node.crypt', passive: true)
                                                    .and_return(double(consumer_count: 0))
    expect(@cs.cs).to eq(Digest::SHA256.digest(configuration[:cluster_secret]))
  end

  it 'permits bootstrap with the actual lite transport adapter type' do
    transport.replace(connected: true, enabled: true)
    stub_const('Legion::Transport::TYPE', 'local')
    expect(@cs.cs).to eq(Digest::SHA256.digest(configuration[:cluster_secret]))
  end

  it 'does not treat disconnected transport as evidence of an empty cluster' do
    transport[:enabled] = true
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('LEGION_MODE').and_return(nil)
    expect { @cs.cs }.to raise_error(initialization_error)
  end

  it 'converges on a delayed peer reply instead of generating another key' do
    transport[:connected] = true
    peer_secret = SecureRandom.hex(32)
    published = Queue.new
    request = double('cluster secret request')
    allow(Legion::Transport::Messages::RequestClusterSecret).to receive(:new).and_return(request)
    allow(request).to receive(:publish) { published << true }
    responder = Thread.new do
      published.pop
      @cs.set_cluster_secret(peer_secret, false)
    end

    expect(@cs.cs).to eq(Digest::SHA256.digest(peer_secret))
    responder.join
  ensure
    responder&.kill
    responder&.join
  end

  it 'bounds discovery even when an upstream provider stalls' do
    configuration[:cluster_secret_timeout] = 0.01
    allow(@cs).to receive(:from_vault) { sleep(10) }
    Timeout.timeout(1) do
      expect { @cs.cs }.to raise_error(initialization_error) do |error|
        expect(error.cause).to be_a(Timeout::Error)
      end
    end
  end

  it 'rejects invalid key configuration before discovery' do
    configuration[:cluster_length] = -1
    expect(@cs).not_to receive(:from_transport)
    expect { @cs.cs }.to raise_error(initialization_error)
  end

  it 'rejects an unbounded readiness timeout' do
    configuration[:cluster_secret_timeout] = Float::INFINITY
    expect { @cs.cs }.to raise_error(initialization_error)
  end

  it 'rejects malformed configured secrets rather than silently replacing them' do
    configuration[:cluster_secret] = 'invalid'
    expect(@cs).not_to receive(:generate_secure_random)
    expect { @cs.find_cluster_secret }.to raise_error(initialization_error)
  end

  it 'cancels discovery when shutdown begins while waiting for a peer' do
    transport[:connected] = true
    request = double('cluster secret request')
    allow(Legion::Transport::Messages::RequestClusterSecret).to receive(:new).and_return(request)
    allow(request).to receive(:publish) { client[:shutting_down] = true }
    expect { @cs.cs }.to raise_error(initialization_error)
  end

  it 'rejects cached keys during shutdown' do
    @cs.cs
    client[:shutting_down] = true
    expect { @cs.cs }.to raise_error(initialization_error)
  end

  it 'preserves the cause of a persistent initialization failure' do
    failure = RuntimeError.new('discovery unavailable')
    allow(@cs).to receive(:find_cluster_secret).and_raise(failure)
    expect { @cs.cs }.to raise_error(initialization_error) do |error|
      expect(error.cause).to equal(failure)
    end
  end

  it 'keeps a valid local secret when publishing it to Vault fails' do
    secret = SecureRandom.hex(32)
    configuration[:vault][:connected] = true
    configuration[:vault][:push_cluster_secret] = true
    allow(Legion::Crypt).to receive(:write).and_raise(StandardError, 'permission denied')
    @cs.set_cluster_secret(secret)
    expect(@cs.cs).to eq(Digest::SHA256.digest(secret))
  end

  it 'round trips the current secret through Vault and refreshes after rotation' do
    vault_store = {}
    initial_secret = SecureRandom.hex(32)
    rotated_secret = SecureRandom.hex(32)
    configuration[:vault].merge!(connected: true, read_cluster_secret: true, push_cluster_secret: true)
    allow(Legion::Crypt).to receive(:write) { |path, **data| vault_store[path] = data }
    allow(Legion::Crypt).to receive(:exist?) { |path| vault_store.key?(path) }
    allow(Legion::Crypt).to receive(:get) { |path| vault_store[path] }

    @cs.set_cluster_secret(initial_secret)
    expect(@cs.cs).to eq(Digest::SHA256.digest(initial_secret))
    configuration[:cluster_secret] = nil
    expect(@cs.cs).to eq(Digest::SHA256.digest(initial_secret))
    @cs.set_cluster_secret(rotated_secret, false)
    expect(@cs.cs).to eq(Digest::SHA256.digest(rotated_secret))
  end
end
