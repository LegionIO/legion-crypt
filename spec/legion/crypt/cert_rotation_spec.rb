# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/mtls'
require 'legion/crypt/cert_rotation'

RSpec.describe Legion::Crypt::CertRotation do
  subject(:rotation) { described_class.new }

  let(:cert_data) { { cert: 'certificate', key: 'private-key', ca_chain: [], serial: 'original', expiry: Time.now + 86_400 } }
  let(:security) { { mtls: { enabled: true, renewal_window: 0.5 } } }
  let(:events) { Queue.new }

  around do |example|
    original_security = Legion::Settings[:security]
    original_client = Legion::Settings[:client]
    Legion::Settings.set_prop(:security, security)
    Legion::Settings.set_prop(:client, { name: 'test-node' })
    example.run
  ensure
    Legion::Settings.set_prop(:security, original_security)
    Legion::Settings.set_prop(:client, original_client)
  end

  before do
    allow(Legion::Crypt::Mtls).to receive(:issue_cert).and_return(cert_data)
    stub_const('Legion::Events', double('Events'))
    allow(Legion::Events).to receive(:emit) { |name, **payload| events << [name, payload] }
    stub_const('Legion::Crypt::CertRotation::INITIAL_RETRY_DELAY', 0.02)
    stub_const('Legion::Crypt::CertRotation::MAX_RETRY_DELAY', 0.08)
  end

  after { rotation.stop }

  it 'recovers from failed initial issuance and emits only the successful rotation' do
    attempts = 0
    allow(Legion::Crypt::Mtls).to receive(:issue_cert) do
      attempts += 1
      raise IOError, 'Vault unavailable' if attempts == 1

      cert_data
    end
    expect(rotation.needs_renewal?).to be(true)
    rotation.start
    event = Timeout.timeout(1) { events.pop }
    expect(attempts).to eq(2)
    expect(event).to eq(['cert.rotated', { serial: 'original', expiry: cert_data[:expiry] }])
    expect(rotation.current_cert).to eq(cert_data)
    expect(rotation.needs_renewal?).to be(false)
  end

  it 'preserves the last certificate through a failed renewal and retries the replacement' do
    attempts = 0
    failed = Queue.new
    original = cert_data.merge(expiry: Time.now + 0.2)
    replacement = cert_data.merge(serial: 'replacement')
    allow(Legion::Crypt::Mtls).to receive(:issue_cert) do
      attempts += 1
      if attempts == 2
        failed << true
        raise IOError, 'temporary PKI outage'
      end
      attempts == 1 ? original : replacement
    end
    rotation.start
    Timeout.timeout(1) do
      events.pop
      failed.pop
    end
    expect(rotation.current_cert).to eq(original)
    expect(Timeout.timeout(1) { events.pop }.last[:serial]).to eq('replacement')
    expect(rotation.current_cert).to eq(replacement)
    expect(attempts).to eq(3)
  end

  it 'renews short-lived certificates before expiry with the default check interval' do
    original = cert_data.merge(expiry: Time.now + 1)
    attempts = 0
    allow(Legion::Crypt::Mtls).to receive(:issue_cert) do
      attempts += 1
      attempts == 1 ? original : cert_data.merge(serial: 'renewed')
    end
    rotation.start
    Timeout.timeout(2) do
      events.pop
      events.pop
    end
    expect(Time.now).to be < original[:expiry]
    expect(rotation.current_cert[:serial]).to eq('renewed')
  end

  it 'honors the configured fraction of remaining certificate lifetime' do
    security[:mtls][:renewal_window] = 0.25
    issued = Time.now
    allow(Time).to receive(:now).and_return(issued)
    allow(Legion::Crypt::Mtls).to receive(:issue_cert).and_return(cert_data.merge(expiry: issued + 100))
    rotation.rotate!
    allow(Time).to receive(:now).and_return(issued + 74)
    expect(rotation.needs_renewal?).to be(false)
    allow(Time).to receive(:now).and_return(issued + 75)
    expect(rotation.needs_renewal?).to be(true)
  end

  it 'rejects false renewal policy instead of silently using a default' do
    rotation.rotate!
    Legion::Settings.set_prop(:security, { mtls: { enabled: true, renewal_window: false } })
    expect { rotation.needs_renewal? }.to raise_error(ArgumentError)
  end

  it 'backs off failed issuance without spinning and caps successive retry delays' do
    stub_const('Legion::Crypt::CertRotation::INITIAL_RETRY_DELAY', 0.01)
    stub_const('Legion::Crypt::CertRotation::MAX_RETRY_DELAY', 0.02)
    attempts = []
    allow(Legion::Crypt::Mtls).to receive(:issue_cert) do
      attempts << Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise IOError, 'PKI unavailable' if attempts.size < 10

      cert_data
    end
    rotation.start
    Timeout.timeout(1) { events.pop }
    intervals = attempts.each_cons(2).map { |first, second| second - first }
    expect(intervals.first).to be >= 0.008
    expect(intervals.drop(1)).to all(be >= 0.016)
    expect(attempts.size).to eq(10)
  end

  it 'interrupts a pending renewal wait and finishes the worker on stop' do
    worker_started = Queue.new
    allow(Legion::Crypt::Mtls).to receive(:issue_cert) do
      worker_started << Thread.current
      cert_data
    end
    rotation.start
    worker = Timeout.timeout(1) { worker_started.pop }
    Timeout.timeout(1) { events.pop }
    Timeout.timeout(0.5) { rotation.stop }
    expect(worker.alive?).to be(false)
    expect(rotation.current_cert).to eq(cert_data)
  end

  it 'discards a late issuance after stop and permits a clean restart' do
    worker = nil
    release = nil
    entered = Queue.new
    release = Queue.new
    allow(Legion::Crypt::Mtls).to receive(:issue_cert) do
      entered << Thread.current
      release.pop
      cert_data
    end
    rotation.start
    worker = Timeout.timeout(1) { entered.pop }
    rotation.stop(deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.02)
    rotation.start
    release << true
    Timeout.timeout(1) { worker.join }
    expect(rotation.current_cert).to be_nil
    expect(events).to be_empty
    expect(entered).to be_empty

    allow(Legion::Crypt::Mtls).to receive(:issue_cert).and_return(cert_data.merge(serial: 'restarted'))
    rotation.start
    expect(Timeout.timeout(1) { events.pop }.last[:serial]).to eq('restarted')
  ensure
    release << true if release && worker&.alive?
    worker&.join(1)
  end

  it 'does not request certificates when mTLS is disabled' do
    security[:mtls][:enabled] = false
    expect(Legion::Crypt::Mtls).not_to receive(:issue_cert)
    rotation.start
    expect(rotation.running?).to be(false)
  end

  it 'keeps the usable certificate when PKI returns an already-expired replacement' do
    rotation.rotate!
    allow(Legion::Crypt::Mtls).to receive(:issue_cert).and_return(cert_data.merge(expiry: Time.now - 1))
    expect { rotation.rotate! }.to raise_error(RuntimeError, /expired certificate/)
    expect(rotation.current_cert).to eq(cert_data)
    expect(events.size).to eq(1)
  end
end
