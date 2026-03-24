# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/mtls'
require 'legion/crypt/cert_rotation'

RSpec.describe Legion::Crypt::CertRotation do
  let(:cert_data) do
    {
      cert:     "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
      key:      "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
      ca_chain: [],
      serial:   '01:02',
      expiry:   Time.now + 86_400
    }
  end

  before do
    allow(Legion::Crypt::Mtls).to receive(:enabled?).and_return(true)
    allow(Legion::Crypt::Mtls).to receive(:issue_cert).and_return(cert_data)
    stub_const('Legion::Settings', Module.new)
    allow(Legion::Settings).to receive(:[]).and_return({})
    allow(Legion::Settings).to receive(:[]).with(:client).and_return({ name: 'test-node' })
  end

  describe '#initialize' do
    it 'creates instance with default check_interval of 43200' do
      rotation = described_class.new
      expect(rotation.check_interval).to eq 43_200
    end

    it 'accepts a custom check_interval' do
      rotation = described_class.new(check_interval: 60)
      expect(rotation.check_interval).to eq 60
    end

    it 'does not start a thread on initialize' do
      rotation = described_class.new
      expect(rotation.running?).to be false
    end
  end

  describe '#current_cert' do
    it 'returns nil before start' do
      rotation = described_class.new
      expect(rotation.current_cert).to be_nil
    end
  end

  describe '#rotate!' do
    it 'calls Mtls.issue_cert with node name from settings' do
      rotation = described_class.new
      allow(Legion::Settings).to receive(:[]).with(:client).and_return({ name: 'my-node' })
      expect(Legion::Crypt::Mtls).to receive(:issue_cert).with(common_name: 'my-node').and_return(cert_data)
      rotation.rotate!
    end

    it 'stores the new cert as current_cert' do
      rotation = described_class.new
      rotation.rotate!
      expect(rotation.current_cert).to eq cert_data
    end

    it 'stores the issued_at time' do
      rotation = described_class.new
      before = Time.now
      rotation.rotate!
      expect(rotation.issued_at).to be >= before
    end

    it 'emits cert.rotated event when Legion::Events is defined' do
      stub_const('Legion::Events', double('Events'))
      expect(Legion::Events).to receive(:emit).with('cert.rotated', hash_including(:serial))
      rotation = described_class.new
      rotation.rotate!
    end

    it 'does not raise when Legion::Events is not defined' do
      hide_const('Legion::Events') if defined?(Legion::Events)
      rotation = described_class.new
      expect { rotation.rotate! }.not_to raise_error
    end
  end

  describe '#needs_renewal?' do
    it 'returns false when current_cert is nil' do
      rotation = described_class.new
      expect(rotation.needs_renewal?).to be false
    end

    it 'returns false when cert has more than 50% TTL remaining' do
      rotation = described_class.new
      rotation.instance_variable_set(:@current_cert, cert_data)
      rotation.instance_variable_set(:@issued_at, Time.now)
      # expiry is 24h from now, issued_at is now => 100% remaining
      expect(rotation.needs_renewal?).to be false
    end

    it 'returns true when less than 50% TTL remains' do
      rotation = described_class.new
      # issued_at 13 hours ago, expiry 11 hours from now => 24h total, 11/24 ~ 46% remaining
      issued = Time.now - (13 * 3600)
      expiry = Time.now + (11 * 3600)
      data = cert_data.merge(expiry: expiry)
      rotation.instance_variable_set(:@current_cert, data)
      rotation.instance_variable_set(:@issued_at, issued)
      expect(rotation.needs_renewal?).to be true
    end
  end

  describe '#start and #stop' do
    it 'starts a background thread' do
      rotation = described_class.new(check_interval: 3600)
      rotation.start
      expect(rotation.running?).to be true
      rotation.stop
    end

    it 'stops the thread' do
      rotation = described_class.new(check_interval: 3600)
      rotation.start
      rotation.stop
      expect(rotation.running?).to be false
    end

    it 'does not start when mtls is disabled' do
      allow(Legion::Crypt::Mtls).to receive(:enabled?).and_return(false)
      rotation = described_class.new
      rotation.start
      expect(rotation.running?).to be false
    end

    it 'is idempotent — double start does not spawn a second thread' do
      rotation = described_class.new(check_interval: 3600)
      rotation.start
      t1 = rotation.instance_variable_get(:@thread)
      rotation.start
      t2 = rotation.instance_variable_get(:@thread)
      expect(t1).to eq t2
      rotation.stop
    end
  end
end
