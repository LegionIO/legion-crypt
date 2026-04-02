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
      allow(logging).to receive(:respond_to?).and_return(false)
      allow(logging).to receive(:respond_to?).with(:info).and_return(true)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(true)
      allow(logging).to receive(:info)
      expect(logging).to receive(:log_exception).with(instance_of(StandardError), lex: 'crypt', component_type: :helper)
      @vault.connect_vault
    end

    it 'falls back to Logging.error with backtrace when log_exception unavailable' do
      logging = double('Legion::Logging')
      stub_const('Legion::Logging', logging)
      allow(logging).to receive(:respond_to?).and_return(false)
      allow(logging).to receive(:respond_to?).with(:info).and_return(true)
      allow(logging).to receive(:respond_to?).with(:log_exception).and_return(false)
      allow(logging).to receive(:respond_to?).with(:error).and_return(true)
      allow(logging).to receive(:info)
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

  it '.add_session' do
    expect(@vault.add_session(path: '/test')).to be_a Array
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

  it '.renew_sessions' do
    expect(Legion::Crypt.renew_sessions).to eq []
  end

  # Multi-cluster KV routing: kv_client / logical_client helpers
  #
  # The test object extends both Vault and VaultCluster so that connected_clusters
  # and vault_client are available, mirroring how Legion::Crypt composes them.
  describe 'multi-cluster client routing' do
    let(:kv_path) { 'legion' }
    let(:mock_kv)      { double('kv') }
    let(:mock_logical) { double('logical') }
    let(:mock_cluster_client) do
      dbl = instance_double(Vault::Client)
      allow(dbl).to receive(:kv).with(kv_path).and_return(mock_kv)
      allow(dbl).to receive(:logical).and_return(mock_logical)
      dbl
    end

    # A host object that mixes in both modules so connected_clusters and
    # vault_client are available alongside the Vault KV methods.
    let(:host) do
      obj = Object.new
      obj.extend(Legion::Crypt::VaultCluster)
      obj.extend(Legion::Crypt::Vault)
      obj.sessions = []
      obj
    end

    context 'when clusters are connected' do
      before do
        allow(host).to receive(:connected_clusters).and_return({ primary: { token: 'tok', connected: true } })
        allow(host).to receive(:selected_connected_cluster_name).with(nil).and_return(:primary)
        allow(host).to receive(:vault_client).with(:primary).and_return(mock_cluster_client)
      end

      describe '#kv_client' do
        it 'returns vault_client.kv(kv_path)' do
          expect(host.send(:kv_client)).to eq(mock_kv)
        end

        it 'does not touch the global ::Vault singleton' do
          expect(Vault).not_to receive(:kv)
          host.send(:kv_client)
        end
      end

      describe '#logical_client' do
        it 'returns vault_client.logical' do
          expect(host.send(:logical_client)).to eq(mock_logical)
        end

        it 'does not touch the global ::Vault singleton' do
          expect(Vault).not_to receive(:logical)
          host.send(:logical_client)
        end
      end

      describe '#get' do
        it 'reads through the cluster kv client' do
          secret = double('secret', data: { value: 'secret_val' })
          allow(mock_kv).to receive(:read).with('mypath').and_return(secret)
          result = host.get('mypath')
          expect(result).to eq({ value: 'secret_val' })
        end

        it 'returns nil when the cluster kv client returns nil' do
          allow(mock_kv).to receive(:read).with('missing').and_return(nil)
          expect(host.get('missing')).to be_nil
        end
      end

      describe '#write' do
        it 'writes through the cluster kv client' do
          expect(mock_kv).to receive(:write).with('mypath', key: 'val')
          host.write('mypath', key: 'val')
        end
      end

      describe '#exist?' do
        it 'reads metadata through the cluster kv client' do
          allow(mock_kv).to receive(:read_metadata).with('mypath').and_return(double('meta'))
          expect(host.exist?('mypath')).to be true
        end

        it 'returns false when metadata is nil' do
          allow(mock_kv).to receive(:read_metadata).with('gone').and_return(nil)
          expect(host.exist?('gone')).to be false
        end
      end

      describe '#delete' do
        it 'deletes through the cluster logical client' do
          allow(mock_logical).to receive(:delete).with('secret/mypath').and_return(nil)
          result = host.delete('secret/mypath')
          expect(result[:success]).to be true
        end

        it 'returns success: false on error' do
          allow(mock_logical).to receive(:delete).and_raise(StandardError, 'permission denied')
          result = host.delete('secret/mypath')
          expect(result[:success]).to be false
          expect(result[:error]).to match(/permission denied/)
        end
      end

      describe '#read (logical)' do
        it 'reads through the cluster logical client' do
          lease = double('lease', lease_id: nil, data: { token: 'abc' })
          allow(lease).to receive(:respond_to?).with(:lease_id).and_return(false)
          allow(mock_logical).to receive(:read).and_return(lease)
          result = host.read('database/creds/myrole', nil)
          expect(result).to eq({ token: 'abc' })
        end
      end

      describe 'explicit cluster selection' do
        let(:mock_secondary_kv) { double('kv-secondary') }
        let(:mock_secondary_logical) { double('logical-secondary') }
        let(:mock_secondary_client) do
          dbl = instance_double(Vault::Client)
          allow(dbl).to receive(:kv).with(kv_path).and_return(mock_secondary_kv)
          allow(dbl).to receive(:logical).and_return(mock_secondary_logical)
          dbl
        end

        before do
          allow(host).to receive(:connected_clusters).and_return(
            {
              primary:   { token: 'tok', connected: true },
              secondary: { token: 'tok-2', connected: true }
            }
          )
          allow(host).to receive(:selected_connected_cluster_name).with(:secondary).and_return(:secondary)
          allow(host).to receive(:vault_client).with(:secondary).and_return(mock_secondary_client)
        end

        it 'routes get through the requested cluster client' do
          secret = double('secret', data: { value: 'secondary' })
          allow(mock_secondary_kv).to receive(:read).with('mypath').and_return(secret)

          expect(host.get('mypath', cluster_name: :secondary)).to eq({ value: 'secondary' })
        end

        it 'raises when the requested cluster is not connected' do
          allow(host).to receive(:selected_connected_cluster_name).with(:missing)
                     .and_raise(ArgumentError, 'Vault cluster not connected: missing')

          expect do
            host.get('mypath', cluster_name: :missing)
          end.to raise_error(ArgumentError, /not connected/)
        end
      end
    end

    context 'when no clusters are connected' do
      before do
        allow(host).to receive(:connected_clusters).and_return({})
      end

      let(:global_kv)      { double('global_kv') }
      let(:global_logical) { double('global_logical') }

      before do
        allow(Vault).to receive(:kv).with(kv_path).and_return(global_kv)
        allow(Vault).to receive(:logical).and_return(global_logical)
      end

      describe '#kv_client' do
        it 'falls back to the global ::Vault.kv client' do
          expect(host.send(:kv_client)).to eq(global_kv)
        end

        it 'does not call vault_client' do
          expect(host).not_to receive(:vault_client)
          host.send(:kv_client)
        end
      end

      describe '#logical_client' do
        it 'falls back to the global ::Vault.logical client' do
          expect(host.send(:logical_client)).to eq(global_logical)
        end

        it 'does not call vault_client' do
          expect(host).not_to receive(:vault_client)
          host.send(:logical_client)
        end
      end

      describe '#get' do
        it 'reads through the global ::Vault kv client' do
          secret = double('secret', data: { val: 1 })
          allow(global_kv).to receive(:read).with('mypath').and_return(secret)
          expect(host.get('mypath')).to eq({ val: 1 })
        end
      end

      describe '#write' do
        it 'writes through the global ::Vault kv client' do
          expect(global_kv).to receive(:write).with('mypath', x: 1)
          host.write('mypath', x: 1)
        end
      end

      describe '#exist?' do
        it 'checks metadata through the global ::Vault kv client' do
          allow(global_kv).to receive(:read_metadata).with('mypath').and_return(double('meta'))
          expect(host.exist?('mypath')).to be true
        end
      end
    end
  end
end
