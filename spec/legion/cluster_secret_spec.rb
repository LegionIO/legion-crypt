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
    expect(@cs.force_cluster_secret).to eq false
  end

  it '.settings_push_vault' do
    expect(@cs.settings_push_vault).to eq false
  end

  it '.only_member?' do
    expect(@cs.only_member?).to eq nil
  end

  it '.push_cs_to_vault' do
    expect(@cs.push_cs_to_vault).to eq false
  end

  describe '#push_cs_to_vault rescue paths' do
    before do
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]).and_call_original
      allow(Legion::Settings[:crypt][:vault]).to receive(:[]).with(:connected).and_return(true)
      allow(Legion::Settings[:crypt]).to receive(:[]).and_call_original
      allow(Legion::Settings[:crypt]).to receive(:[]).with(:cluster_secret).and_return('aabbccdd')
      allow(Legion::Crypt).to receive(:write).and_raise(StandardError, 'permission denied')
    end

    it 'returns false when Vault write raises' do
      expect(@cs.push_cs_to_vault).to eq false
    end

    it 'does not propagate the exception' do
      expect { @cs.push_cs_to_vault }.not_to raise_error
    end

    it 'logs a warning when Legion::Logging is available' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:info)
      expect(logging).to receive(:warn).with(match(/push_cs_to_vault failed/))
      @cs.push_cs_to_vault
    end
  end

  describe '#set_cluster_secret stores value even when Vault push fails' do
    let(:valid_secret) { SecureRandom.hex(16) }

    before do
      allow(@cs).to receive(:settings_push_vault).and_return(true)
      allow(@cs).to receive(:push_cs_to_vault).and_raise(StandardError, 'vault 403')
    end

    it 'raises because push_cs_to_vault propagated — demonstrating the old bug (pre-fix)' do
      # With the old code, push_cs_to_vault raising would prevent the assignment.
      # This spec documents that push_cs_to_vault itself now rescues internally,
      # so set_cluster_secret always completes the Settings assignment.
      # Here we force the raise at the set_cluster_secret level to confirm the fix
      # is in push_cs_to_vault, not set_cluster_secret.
      expect { @cs.set_cluster_secret(valid_secret, true) }.to raise_error(StandardError, 'vault 403')
    end

    context 'when push_cs_to_vault rescues internally (the fix)' do
      before do
        allow(@cs).to receive(:push_cs_to_vault).and_return(false)
      end

      it 'stores cluster_secret in Settings' do
        @cs.set_cluster_secret(valid_secret, true)
        expect(Legion::Settings[:crypt][:cluster_secret]).to eq valid_secret
      end

      it 'sets cs_encrypt_ready to true' do
        @cs.set_cluster_secret(valid_secret, true)
        expect(Legion::Settings[:crypt][:cs_encrypt_ready]).to eq true
      end
    end
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
      allow(Kernel).to receive(:warn)
      result = nil
      expect { result = @cs.from_transport }.not_to raise_error
      expect(result).to be_nil
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

    it 'falls back to Kernel.warn when Legion::Logging is absent' do
      hide_const('Legion::Logging')
      expect(Kernel).to receive(:warn).with(match(/digest error/))
      expect(@cs.cs).to be_nil
    end

    it 'returns nil without raising when Legion::Logging is absent' do
      hide_const('Legion::Logging')
      allow(Kernel).to receive(:warn)
      result = nil
      expect { result = @cs.cs }.not_to raise_error
      expect(result).to be_nil
    end
  end
end
