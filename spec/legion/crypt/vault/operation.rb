# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault/operation'

RSpec.describe Legion::Crypt::Vault::Operation do
  before { Legion::Settings[:crypt][:vault][:operation_timeout] = 0.03 }

  it 'returns the operation result and yields a deadline based on the configured budget' do
    Legion::Settings[:crypt][:vault][:operation_timeout] = 1
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    operation_deadline = nil

    result = described_class.with_timeout(request_id: 'operation-test') do |deadline|
      operation_deadline = deadline
      { renewed: true }
    end

    finished = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    expect(result).to eq(renewed: true)
    expect(operation_deadline).to be_between(started + 1, finished + 1)
  end

  [nil, false, '1', 0, -1, Float::NAN, Float::INFINITY, -Float::INFINITY].each do |timeout|
    it "rejects invalid configured timeout #{timeout.inspect} before executing the operation" do
      Legion::Settings[:crypt][:vault][:operation_timeout] = timeout
      executed = false

      expect { described_class.with_timeout { executed = true } }.to raise_error(ArgumentError)
      expect(executed).to be(false)
    end
  end

  it 'does not execute an operation after its shared deadline has expired' do
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) - 1
    executed = false

    expect { described_class.with_timeout(deadline: deadline) { executed = true } }.to raise_error(Timeout::Error)
    expect(executed).to be(false)
  end

  it 'interrupts a stalled operation and runs its cleanup' do
    cleaned_up = false
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    expect do
      described_class.with_timeout do
        sleep 1
      ensure
        cleaned_up = true
      end
    end.to raise_error(Timeout::Error)

    expect(cleaned_up).to be(true)
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.5
  end

  it 'uses an earlier shared deadline instead of granting the full configured budget' do
    Legion::Settings[:crypt][:vault][:operation_timeout] = 1
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    expect do
      described_class.with_timeout(deadline: started + 0.03) { sleep 1 }
    end.to raise_error(Timeout::Error)

    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.5
  end

  it 'does not let a later shared deadline extend the configured budget' do
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    expect do
      described_class.with_timeout(deadline: started + 1) { sleep 1 }
    end.to raise_error(Timeout::Error)

    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.5
  end

  it 'propagates the original operation error without replacing it with a timeout' do
    failure = ArgumentError.new('invalid operation arguments')

    expect { described_class.with_timeout { raise failure } }.to(raise_error { |error| expect(error).to equal(failure) })
  end
end
