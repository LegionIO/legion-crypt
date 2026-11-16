# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault/cluster'
require 'legion/settings/resolver'
require 'socket'

RSpec.describe Legion::Crypt::Vault::Cluster do
  let(:cluster_alpha) do
    { protocol: 'https', address: 'vault-alpha.example.com', port: 8200, token: 'token-alpha', connected: true }
  end
  let(:cluster_beta) do
    { protocol: 'https', address: 'vault-beta.example.com', port: 8200, token: 'token-beta', connected: false }
  end
  let(:cluster_gamma) do
    { protocol: 'http', address: 'vault-gamma.example.com', port: 8200, token: nil, connected: false }
  end

  let(:test_clusters) { { alpha: cluster_alpha, beta: cluster_beta, gamma: cluster_gamma } }
  let(:default_cluster) { :alpha }

  around do |example|
    original = Legion::Settings[:crypt]
    configuration = Legion::Crypt::Settings.default
    configuration[:vault].merge!(default: default_cluster, clusters: test_clusters)
    Legion::Settings.set_prop(:crypt, configuration)
    example.run
  ensure
    Legion::Settings.set_prop(:crypt, original)
  end

  let(:test_object) do
    obj = Object.new
    obj.extend(described_class)
    obj
  end

  describe '#default_cluster_name' do
    it 'returns the configured default cluster name as a symbol' do
      expect(test_object.default_cluster_name).to eq(:alpha)
    end

    context 'when default is nil' do
      let(:default_cluster) { nil }

      it 'returns the first cluster key' do
        expect(test_object.default_cluster_name).to eq(:alpha)
      end
    end
  end

  describe '#cluster' do
    it 'returns the default cluster config when no name is given' do
      expect(test_object.cluster).to eq(cluster_alpha)
    end

    it 'returns the named cluster config' do
      expect(test_object.cluster(:beta)).to eq(cluster_beta)
    end

    it 'returns nil for an unknown cluster name' do
      expect(test_object.cluster(:unknown)).to be_nil
    end
  end

  describe '#connected_clusters' do
    it 'returns only clusters with a token AND connected=true' do
      result = test_object.connected_clusters
      expect(result.keys).to eq([:alpha])
    end

    it 'excludes clusters without a token' do
      expect(test_object.connected_clusters).not_to have_key(:gamma)
    end

    it 'excludes clusters that have a token but are not connected' do
      expect(test_object.connected_clusters).not_to have_key(:beta)
    end
  end

  describe '#vault_client' do
    after { test_object.clear_vault_clients }

    it 'reuses unchanged clients while isolating different clusters' do
      alpha = test_object.vault_client(:alpha)
      expect(test_object.vault_client).to equal(alpha)
      expect(test_object.vault_client(:beta)).not_to equal(alpha)
      expect(test_object.vault_client(:unknown)).to be_nil
    end

    it 'replaces clients when any connection attribute changes' do
      changes = [
        [:address, 'other.example.com', :address, 'https://other.example.com:8200'],
        [:protocol, 'http', :address, 'http://other.example.com:8200'],
        [:port, 8201, :address, 'http://other.example.com:8201'],
        [:namespace, 'tenant', :namespace, 'tenant'],
        [:tls, { verify: 'none' }, :ssl_verify, false],
        [:token, 'replacement-token', :token, 'replacement-token']
      ]
      changes.each do |key, value, attribute, expected|
        previous = test_object.vault_client(:alpha)
        cluster_alpha[key] = value
        replacement = test_object.vault_client(:alpha)
        expect(replacement).not_to equal(previous)
        expect(replacement.public_send(attribute)).to eq(expected)
      end
    end

    it 'detects in-place namespace changes and inherited namespace changes' do
      Legion::Settings[:crypt][:vault][:vault_namespace] = +'first'
      first = test_object.vault_client(:alpha)
      Legion::Settings[:crypt][:vault][:vault_namespace].replace('second')
      second = test_object.vault_client(:alpha)
      expect(second).not_to equal(first)
      expect(second.namespace).to eq('second')
      cluster_alpha[:namespace] = nil
      expect(test_object.vault_client(:alpha).namespace).to be_nil
    end

    it 'keeps the current client when a grant replaces its token' do
      client = test_object.vault_client(:alpha)

      test_object.publish_vault_grant(cluster_name: :alpha, client: client, auth_method: 'kerberos',
                                      grant: { token: 'renewed-token', lease_duration: 3600, renewable: true })

      expect(test_object.vault_client(:alpha)).to equal(client)
      expect(client.token).to eq('renewed-token')
      expect(cluster_alpha).to include(token: 'renewed-token', connected: true, relogin_required: false, auth_method: 'kerberos')
    end

    it 'keeps the top-level connected flag current for named clusters' do
      client = test_object.vault_client(:alpha)
      expect(Legion::Settings[:crypt][:vault][:connected]).to be(false)

      test_object.publish_vault_grant(cluster_name: :alpha, client: client, auth_method: 'kerberos',
                                      grant: { token: 'renewed-token', lease_duration: 3600, renewable: true })
      expect(Legion::Settings[:crypt][:vault][:connected]).to be(true)

      test_object.disconnect_vault_grant(cluster_name: :alpha, token: 'renewed-token', relogin_required: false)
      expect(Legion::Settings[:crypt][:vault][:connected]).to be(false)
    end

    it 'publishes grants into the live configuration after a settings rebuild' do
      client = test_object.vault_client(:alpha)
      Legion::Settings.loader.mark_dirty!
      Legion::Settings.loader.to_hash
      live = Legion::Settings[:crypt][:vault][:clusters][:alpha]
      expect(live).not_to equal(cluster_alpha)

      expires_at = test_object.publish_vault_grant(cluster_name: :alpha, client: client, auth_method: 'ldap',
                                                   grant: { token: 'rotated-token', lease_duration: 60, renewable: false })

      expect(live).to include(token: 'rotated-token', expires_at: expires_at, connected: true)
      expect(cluster_alpha[:token]).to eq('token-alpha')
      expect(test_object.vault_client(:alpha)).to equal(client)
    end

    it 'rejects a grant when the current token differs from the one it replaces' do
      client = test_object.vault_client(:alpha)

      expect do
        test_object.publish_vault_grant(cluster_name: :alpha, client: client, auth_method: 'kerberos', current_token: 'superseded-token',
                                        grant: { token: 'late-token', lease_duration: 60 })
      end.to raise_error(Legion::Crypt::Vault::GrantRejectedError)
      expect(cluster_alpha[:token]).to eq('token-alpha')
      expect(client.token).to eq('token-alpha')
    end

    it 'removes a cluster from the cache but keeps its retained client usable until shutdown' do
      client = test_object.vault_client(:alpha)
      connection = Faraday.new do |builder|
        builder.adapter(:test) do |stub|
          stub.get('/v1/sys/health') { [200, {}, Legion::JSON.dump({ initialized: true })] }
        end
      end
      allow(client).to receive(:build_connection).and_return(connection)
      test_clusters.delete(:alpha)

      expect(test_object.vault_client(:alpha)).to be_nil
      expect(client.sys.health_status.initialized?).to be(true)
      test_object.clear_vault_clients
      expect { client.sys.health_status }.to raise_error(IOError)
    end

    it 'keeps token renewal, lease reissue and revocation available through a displaced client' do
      client = test_object.vault_client(:alpha)
      revoked = []
      reads = 0
      connection = Faraday.new do |builder|
        builder.adapter(:test) do |stub|
          stub.get('/v1/database/creds/app') do
            reads += 1
            [200, {}, Legion::JSON.dump({ data: { username: "user-#{reads}" }, lease_id: "lease-#{reads}",
                                         lease_duration: 3600, renewable: true })]
          end
          stub.put('/v1/auth/token/renew-self') do
            [200, {}, Legion::JSON.dump({ auth: { lease_duration: 3600, renewable: true } })]
          end
          stub.put('/v1/sys/leases/revoke') do |request|
            revoked << Legion::JSON.load(request.body)[:lease_id]
            [204, {}, nil]
          end
        end
      end
      allow(client).to receive(:build_connection).and_return(connection)
      manager = Legion::Crypt::Vault::Leases.new
      manager.start(definitions: { database: { path: 'database/creds/app' } }, client: client)
      cluster_alpha[:token] = 'new-token'
      expect(test_object.vault_client(:alpha)).not_to equal(client)

      expect(client.auth_token.renew_self.auth.lease_duration).to eq(3600)
      expect(manager.reissue_lease(:database)).to be(true)
      expect(manager.fetch(:database, :username)).to eq('user-2')
      manager.shutdown
      expect(revoked).to contain_exactly('lease-1', 'lease-2')
      test_object.clear_vault_clients
      expect { client.sys.health_status }.to raise_error(IOError)
    ensure
      manager&.reset!
    end

    it 'rejects a late authentication result after its client has been displaced' do
      previous = test_object.vault_client(:alpha)
      cluster_alpha[:namespace] = 'replacement-namespace'
      current = test_object.vault_client(:alpha)

      expect do
        test_object.publish_vault_grant(cluster_name: :alpha, client: previous, grant: { token: 'stale-token' }, auth_method: 'ldap')
      end.to raise_error(Legion::Crypt::Vault::GrantRejectedError)
      expect(test_object.vault_client(:alpha)).to equal(current)
      expect(current.token).to eq('token-alpha')
      expect(cluster_alpha[:token]).to eq('token-alpha')
    end

    it 'clears every entry even when one client cannot shut down' do
      alpha = test_object.vault_client(:alpha)
      beta = test_object.vault_client(:beta)
      allow(alpha).to receive(:shutdown).and_raise(IOError, 'failed shutdown')
      allow(beta).to receive(:shutdown).and_call_original
      test_object.clear_vault_clients
      expect(beta).to have_received(:shutdown).once
      expect(test_object.vault_client(:alpha)).not_to equal(alpha)
      expect(test_object.vault_client(:beta)).not_to equal(beta)
    end

    it 'bounds retirement without blocking a replacement client' do
      Legion::Settings[:crypt][:vault][:operation_timeout] = 0.03
      previous = test_object.vault_client(:alpha)
      allow(previous).to receive(:shutdown) { sleep 10 }
      cluster_alpha[:address] = 'replacement.example.com'
      replacement = Timeout.timeout(0.5) { test_object.vault_client(:alpha) }
      expect(replacement.address).to eq('https://replacement.example.com:8200')
      expect(test_object.vault_client(:alpha)).to equal(replacement)
    end

    it 'uses a Vault-backed CA from another cached cluster to verify the TLS peer' do
      key = OpenSSL::PKey::EC.generate('prime256v1')
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = 1
      certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse('/CN=localhost')
      certificate.public_key = key
      certificate.not_before = Time.now - 60
      certificate.not_after = Time.now + 3600
      extensions = OpenSSL::X509::ExtensionFactory.new
      extensions.subject_certificate = extensions.issuer_certificate = certificate
      certificate.add_extension(extensions.create_extension('basicConstraints', 'CA:TRUE', true))
      certificate.add_extension(extensions.create_extension('subjectAltName', 'IP:127.0.0.1'))
      certificate.sign(key, OpenSSL::Digest.new('SHA256'))
      listener = TCPServer.new('127.0.0.1', 0)
      context = OpenSSL::SSL::SSLContext.new
      context.cert = certificate
      context.key = key
      server = OpenSSL::SSL::SSLServer.new(listener, context)
      responder = Thread.new do
        socket = server.accept
        loop do
          line = socket.gets
          break if line.nil? || line == "\r\n"
        end
        body = Legion::JSON.dump({ initialized: true })
        socket.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
      ensure
        socket&.close
      end
      primary = test_object.vault_client(:alpha)
      connection = Faraday.new do |builder|
        builder.adapter(:test) do |stub|
          stub.get('/v1/secret/audit-ca') { [200, {}, Legion::JSON.dump({ data: { pem: certificate.to_pem } })] }
        end
      end
      allow(primary).to receive(:build_connection).and_return(connection)
      allow(Legion::Crypt).to receive(:read) { |path| test_object.vault_client(:alpha).logical.read(path: path).data }
      cluster_beta.merge!(address: '127.0.0.1', port: listener.addr[1], tls: { ca: 'vault://secret/audit-ca#pem' })

      secondary = test_object.vault_client(:beta)
      expect(secondary.sys.health_status.initialized?).to be(true)
      expect(secondary.ssl_verify).to be(true)
      expect(secondary.ca).to eq(certificate.to_pem)
    ensure
      listener&.close
      responder&.kill
      responder&.join
    end

    it 'rejects a client whose TLS construction finishes after the cache is cleared' do
      entered = Queue.new
      release = Queue.new
      allow(Legion::Crypt::TLS).to receive(:resolve).and_wrap_original do |original, *args|
        entered << true
        release.pop
        original.call(*args)
      end
      worker = Thread.new do
        test_object.vault_client(:alpha)
      rescue IOError => e
        e
      end
      Timeout.timeout(1) { entered.pop }
      test_object.clear_vault_clients
      release << true
      Timeout.timeout(1) { worker.join }

      expect(worker.value).to be_a(IOError)
    ensure
      worker&.kill
      worker&.join
    end

    it 'rejects explicitly configured TLS material that cannot be resolved' do
      cluster_beta[:tls] = { ca: 'vault://secret/missing#pem' }
      allow(Legion::Crypt).to receive(:read).with('secret/missing').and_return(nil)

      expect { test_object.vault_client(:beta) }.to raise_error(IOError)
    end
  end
end
