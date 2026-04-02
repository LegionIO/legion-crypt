# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/spiffe'
require 'legion/crypt/spiffe/workload_api_client'
require 'legion/crypt/spiffe/svid_rotation'

RSpec.describe Legion::Crypt::Spiffe::SvidRotation do
  let(:mock_svid) do
    Legion::Crypt::Spiffe::X509Svid.new(
      Legion::Crypt::Spiffe.parse_id('spiffe://test.local/workload/test'),
      '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----',
      '-----BEGIN EC PRIVATE KEY-----\nMIIB...\n-----END EC PRIVATE KEY-----',
      nil,
      Time.now + 3600
    )
  end

  let(:mock_client) { instance_double(Legion::Crypt::Spiffe::WorkloadApiClient, fetch_x509_svid: mock_svid) }

  before do
    stub_const('Legion::Settings', Module.new)
    allow(Legion::Settings).to receive(:[]).with(:security).and_return(
      { spiffe: { enabled: true, socket_path: '/tmp/fake.sock', trust_domain: 'test.local' } }
    )
  end

  subject(:rotation) { described_class.new(check_interval: 60, client: mock_client) }

  describe '#running?' do
    it 'returns false before start is called' do
      expect(rotation.running?).to be false
    end
  end

  describe '#rotate!' do
    it 'fetches and stores the SVID' do
      rotation.rotate!
      expect(rotation.current_svid).to eq(mock_svid)
    end

    it 'returns the new SVID' do
      result = rotation.rotate!
      expect(result).to eq(mock_svid)
    end

    it 'raises when the client raises' do
      allow(mock_client).to receive(:fetch_x509_svid).and_raise(Legion::Crypt::Spiffe::SvidError, 'fetch failed')
      expect { rotation.rotate! }.to raise_error(Legion::Crypt::Spiffe::SvidError, /fetch failed/)
    end
  end

  describe '#needs_renewal?' do
    it 'returns true when no SVID has been fetched yet' do
      expect(rotation.needs_renewal?).to be true
    end

    it 'returns false when the SVID has plenty of time left' do
      rotation.rotate!
      # SVID expires in 3600s; at 50% window, renewal fires below 1800s remaining.
      # We just rotated so ~3600s remain — no renewal needed.
      expect(rotation.needs_renewal?).to be false
    end

    it 'returns true when the SVID has expired' do
      expired_svid = Legion::Crypt::Spiffe::X509Svid.new(
        Legion::Crypt::Spiffe.parse_id('spiffe://test.local/workload/test'),
        'cert', 'key', nil, Time.now - 1
      )
      allow(mock_client).to receive(:fetch_x509_svid).and_return(expired_svid)
      rotation.rotate!
      expect(rotation.needs_renewal?).to be true
    end

    it 'returns true when past the renewal window fraction' do
      # SVID expires in 10s, issued 15s ago (110% of TTL has elapsed → expired).
      # Use a nearly-expired case: expires in 1s, issued 19s ago → 95% elapsed > 50% window.
      almost_expired_svid = Legion::Crypt::Spiffe::X509Svid.new(
        Legion::Crypt::Spiffe.parse_id('spiffe://test.local/workload/test'),
        'cert', 'key', nil, Time.now + 1
      )
      allow(mock_client).to receive(:fetch_x509_svid).and_return(almost_expired_svid)
      rotation.rotate!
      # Manually backdate @issued_at so fraction calculation shows > 50% elapsed.
      rotation.instance_variable_set(:@issued_at, Time.now - 19)
      expect(rotation.needs_renewal?).to be true
    end
  end

  describe '#start and #stop' do
    it 'does not start when SPIFFE is disabled' do
      allow(Legion::Settings).to receive(:[]).with(:security).and_return(
        { spiffe: { enabled: false } }
      )
      rotation.start
      expect(rotation.running?).to be false
    end

    it 'starts and stops the rotation thread' do
      rotation.start
      expect(rotation.running?).to be true
      rotation.stop
      expect(rotation.running?).to be false
    end

    it 'is idempotent: calling start twice does not create two threads' do
      rotation.start
      thread1 = rotation.instance_variable_get(:@thread)
      rotation.start
      thread2 = rotation.instance_variable_get(:@thread)
      expect(thread1).to eq(thread2)
    ensure
      rotation.stop
    end

    it 'keeps the thread reference when stop times out' do
      stuck_thread = instance_double(Thread, alive?: true)
      allow(stuck_thread).to receive(:wakeup)
      allow(stuck_thread).to receive(:join)
      rotation.instance_variable_set(:@thread, stuck_thread)
      rotation.instance_variable_set(:@running, true)

      rotation.stop

      expect(rotation.instance_variable_get(:@thread)).to eq(stuck_thread)
    end
  end
end
