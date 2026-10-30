# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/vault_client'
require 'tempfile'

RSpec.describe Legion::Crypt::VaultClient do
  let(:address) { 'https://vault.example:8200' }
  let(:client) { described_class.new(address: address, token: 'initial-token', namespace: 'tenant/team') }
  let(:stubs) { Faraday::Adapter::Test::Stubs.new }
  let(:connections) { [] }

  before do
    allow(Faraday).to receive(:new).and_wrap_original do |original, **options, &configure|
      connection = original.call(**options) do |builder|
        configure.call(builder)
        builder.adapter :test, stubs
      end
      allow(connection).to receive(:close).and_call_original
      connections << connection
      connection
    end
  end

  after do
    client.shutdown
    stubs.verify_stubbed_calls
  end

  def json_response(data:, status: 200, **)
    [status, { 'Content-Type' => 'application/json' }, Legion::JSON.dump(data)]
  end

  def certificate_for(key:, common_name:, serial:, **)
    OpenSSL::X509::Certificate.new.tap do |certificate|
      certificate.version = 2
      certificate.serial = serial
      certificate.subject = OpenSSL::X509::Name.parse("/CN=#{common_name}")
      certificate.issuer = certificate.subject
      certificate.public_key = key.public_key
      certificate.not_before = Time.now - 60
      certificate.not_after = Time.now + 3600
      factory = OpenSSL::X509::ExtensionFactory.new(certificate, certificate)
      certificate.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
      certificate.add_extension(factory.create_extension('keyUsage', 'keyCertSign,digitalSignature', true))
      certificate.sign(key, OpenSSL::Digest.new('SHA256'))
    end
  end

  describe 'logical secrets' do
    it 'decodes nested symbol keys and dynamic-secret lease metadata without inventing auth' do
      stubs.get('/v1/database/creds/app') do |env|
        expect(env.request_headers).to include('X-Vault-Token' => 'initial-token', 'X-Vault-Namespace' => 'tenant/team')
        json_response(data: {
                        data: { username: 'app-user', credentials: { password: 'secret-value' } },
                        lease_id: 'database/creds/app/lease-1', lease_duration: 120, renewable: true
                      })
      end

      secret = client.logical.read(path: 'database/creds/app')
      expect(secret.data).to eq(username: 'app-user', credentials: { password: 'secret-value' })
      expect(secret.lease_id).to eq('database/creds/app/lease-1')
      expect(secret.lease_duration).to eq(120)
      expect(secret).to be_renewable
      expect(secret.auth).to be_nil
      expect(secret.inspect).not_to include('secret-value')
    end

    it 'sends JSON PUT bodies and decodes authentication rather than treating them as secret data' do
      stubs.put('/v1/auth/approle/login') do |env|
        expect(env.request_headers['Content-Type']).to eq('application/json')
        expect(Legion::JSON.load(env.body)).to eq(role_id: 'role-id', secret_id: 'secret-id')
        json_response(data: {
                        auth: { client_token: 'login-token', lease_duration: 300, renewable: true,
                                policies: %w[default application], metadata: { role: { name: 'application' } } }
                      })
      end

      secret = client.logical.write(path: 'auth/approle/login', data: { role_id: 'role-id', secret_id: 'secret-id' })
      expect(secret.data).to be_nil
      expect(secret.auth.client_token).to eq('login-token')
      expect(secret.auth.lease_duration).to eq(300)
      expect(secret.auth).to be_renewable
      expect(secret.auth.policies).to eq(%w[default application])
      expect(secret.auth.metadata).to eq(role: { name: 'application' })
      expect(secret.auth.inspect).not_to include('login-token')
    end

    it 'treats a missing secret as nil even when the 404 body is not JSON' do
      stubs.get('/v1/secret/missing') { [404, { 'Content-Type' => 'text/plain' }, 'not found'] }
      expect(client.logical.read(path: 'secret/missing')).to be_nil
    end

    it 'does not manufacture a secret for an empty successful response' do
      stubs.put('/v1/secret/empty') { [204, {}, ''] }
      stubs.get('/v1/secret/empty') { [200, {}, ''] }
      expect(client.logical.write(path: 'secret/empty', data: {})).to be_nil
      expect(client.logical.read(path: 'secret/empty')).to be_nil
    end

    it 'deletes secrets and propagates denial instead of reporting success' do
      stubs.delete('/v1/secret/old') { [204, {}, ''] }
      stubs.delete('/v1/secret/protected') { json_response(data: { errors: ['permission denied'] }, status: 403) }
      expect(client.logical.delete(path: 'secret/old')).to be(true)
      expect { client.logical.delete(path: 'secret/protected') }.to raise_error(Legion::Crypt::Vault::HTTPClientError)
    end
  end

  describe 'request credentials and paths' do
    it 'uses current credentials on a reused connection and removes headers when they are cleared' do
      observed = []
      stubs.get('/v1/secret/value') do |env|
        observed << env.request_headers.slice('X-Vault-Token', 'X-Vault-Namespace')
        json_response(data: { data: { value: 'ok' } })
      end
      client.logical.read(path: 'secret/value')
      client.token = 'replacement-token'
      client.namespace = 'other-tenant'
      client.logical.read(path: 'secret/value')
      client.token = nil
      client.namespace = nil
      client.logical.read(path: 'secret/value')

      expect(observed).to eq([
                               { 'X-Vault-Token' => 'initial-token', 'X-Vault-Namespace' => 'tenant/team' },
                               { 'X-Vault-Token' => 'replacement-token', 'X-Vault-Namespace' => 'other-tenant' },
                               {}
                             ])
      expect(connections.size).to eq(1)
      expect(client.inspect).not_to include('initial-token', 'replacement-token')
    end

    it 'preserves a raw Kerberos body and Authorization while keeping the configured namespace' do
      body = "{\n}\n"
      stubs.put('/v1/auth/kerberos/login') do |env|
        expect(env.body).to eq(body)
        expect(env.request_headers).to include('Authorization' => 'Negotiate kerberos-ticket',
                                               'X-Vault-Token' => 'initial-token', 'X-Vault-Namespace' => 'tenant/team')
        json_response(data: { auth: { client_token: 'kerberos-token', renewable: false } })
      end
      result = client.put(path: '/v1/auth/kerberos/login', body: body, headers: { 'Authorization' => 'Negotiate kerberos-ticket' })
      expect(result).to eq(auth: { client_token: 'kerberos-token', renewable: false })
      expect(described_class::Secret.decode(data: result).auth).not_to be_renewable
    end

    it 'escapes reserved characters and dot segments without flattening the path hierarchy' do
      stubs.get('/v1/secret/team%20space/%2E%2E/100%25%3Fx%23frag') do |env|
        expect(env.url.path).to eq('/v1/secret/team%20space/%2E%2E/100%25%3Fx%23frag')
        expect(env.url.query).to be_nil
        expect(env.url.fragment).to be_nil
        json_response(data: { data: { found: true } })
      end
      expect(client.logical.read(path: 'secret/team space/../100%?x#frag').data).to eq(found: true)
    end

    it 'never sends Vault credentials to a host supplied as a logical path' do
      stubs.get('/v1/https%3A//attacker.invalid/secret') do |env|
        expect(env.url.host).to eq('vault.example')
        expect(env.url.scheme).to eq('https')
        json_response(data: { data: { found: true } })
      end
      expect(client.logical.read(path: 'https://attacker.invalid/secret').data).to eq(found: true)
    end

    it 'distinguishes a mount named v1 from an absolute API prefix' do
      stubs.get('/v1/v1/data/entry') { json_response(data: { data: { data: { value: 'versioned' } } }) }
      expect(client.kv(mount: 'v1').read(path: 'entry').data).to eq(value: 'versioned')
    end

    it 'rejects credentials embedded in an address without putting them in the error message' do
      expect { client.address = 'https://user:password@vault.example:8200' }
        .to raise_error(ArgumentError) { |error| expect(error.message).not_to include('password') }
    end
  end

  describe 'KV version 2' do
    it 'unwraps the data envelope while preserving outer lease and auth metadata' do
      stubs.get('/v1/team/secret/data/application/config') do
        json_response(data: {
                        data: { data: { database: { password: 'kv-password' } }, metadata: { version: 3 } },
                        lease_id: 'kv-lease', lease_duration: 30, renewable: true,
                        auth: { client_token: 'kv-token', policies: ['application'] }
                      })
      end
      secret = client.kv(mount: '/team/secret/').read(path: 'application/config')
      expect(secret.data).to eq(database: { password: 'kv-password' })
      expect(secret.lease_id).to eq('kv-lease')
      expect(secret.lease_duration).to eq(30)
      expect(secret).to be_renewable
      expect(secret.auth.client_token).to eq('kv-token')
    end

    it 'trims only boundary slashes without changing Unicode or internal separators' do
      stubs.get('/v1/t%C3%ABam//secret/data/application') do
        json_response(data: { data: { data: { value: 'found' } } })
      end
      expect(client.kv(mount: '///tëam//secret///').read(path: 'application').data).to eq(value: 'found')
    end

    it 'writes the KV envelope with PUT and reads metadata without unwrapping it' do
      stubs.put('/v1/secret/data/application/config') do |env|
        expect(Legion::JSON.load(env.body)).to eq(data: { enabled: true })
        json_response(data: { data: { version: 4 } })
      end
      stubs.get('/v1/secret/metadata/application/config') do
        json_response(data: { data: { current_version: 4, custom_metadata: { owner: 'operations' } } })
      end
      kv = client.kv(mount: 'secret')
      expect(kv.write(path: 'application/config', data: { enabled: true }).data).to eq(version: 4)
      expect(kv.read_metadata(path: 'application/config').data).to eq(current_version: 4, custom_metadata: { owner: 'operations' })
    end

    it 'returns nil for missing KV values and metadata but does not hide access denial' do
      stubs.get('/v1/secret/data/missing') { [404, {}, ''] }
      stubs.get('/v1/secret/metadata/missing') { [404, {}, ''] }
      stubs.get('/v1/secret/data/protected') { json_response(data: { errors: ['denied'] }, status: 403) }
      kv = client.kv(mount: 'secret')
      expect(kv.read(path: 'missing')).to be_nil
      expect(kv.read_metadata(path: 'missing')).to be_nil
      expect { kv.read(path: 'protected') }.to raise_error(Legion::Crypt::Vault::HTTPClientError)
    end
  end

  describe 'system and token endpoints' do
    it 'reads initialized health and symbol-keyed mounts' do
      stubs.get('/v1/sys/health') { json_response(data: { initialized: true, sealed: false }) }
      stubs.get('/v1/sys/mounts') { json_response(data: { data: { 'secret/': { type: 'kv', options: { version: '2' } } } }) }
      expect(client.sys.health_status).to be_initialized
      expect(client.sys.mounts).to eq('secret/': { type: 'kv', options: { version: '2' } })
    end

    it 'renews and revokes the exact lease ID in JSON rather than placing it in the URL' do
      lease_id = 'database/creds/application/lease-1'
      stubs.put('/v1/sys/leases/renew') do |env|
        expect(Legion::JSON.load(env.body)).to eq(lease_id: lease_id)
        json_response(data: { lease_id: lease_id, lease_duration: 600, renewable: true })
      end
      stubs.put('/v1/sys/leases/revoke') do |env|
        expect(Legion::JSON.load(env.body)).to eq(lease_id: lease_id)
        [204, {}, '']
      end
      renewed = client.sys.renew(lease_id: lease_id)
      expect(renewed.lease_id).to eq(lease_id)
      expect(renewed.lease_duration).to eq(600)
      expect(renewed).to be_renewable
      expect(client.sys.revoke(lease_id: lease_id)).to be(true)
    end

    it 'renews and revokes the current token with empty JSON objects' do
      stubs.put('/v1/auth/token/renew-self', '{}') do
        json_response(data: { auth: { client_token: 'renewed-token', lease_duration: 900, renewable: true } })
      end
      stubs.put('/v1/auth/token/revoke-self', '{}') do |env|
        expect(env.request_headers['X-Vault-Token']).to eq('renewed-token')
        [204, {}, '']
      end
      renewed = client.auth_token.renew_self
      expect(renewed.auth.lease_duration).to eq(900)
      expect(renewed.auth).to be_renewable
      client.token = renewed.auth.client_token
      expect(client.auth_token.revoke_self).to be(true)
    end
  end

  describe 'HTTP and transport failures' do
    it 'exposes HTTP status, address, and Vault error messages to permission handlers' do
      stubs.get('/v1/secret/denied') { json_response(data: { errors: ['permission denied', 'policy required'] }, status: 403) }
      expect { client.logical.read(path: 'secret/denied') }.to raise_error(Legion::Crypt::Vault::HTTPClientError) do |error|
        expect(error.code).to eq(403)
        expect(error.address).to eq(address)
        expect(error.errors).to eq(['permission denied', 'policy required'])
        expect(error.message).to include('403', 'permission denied', 'policy required')
      end
    end

    it 'keeps standby status recognizable even without a JSON error envelope' do
      stubs.get('/v1/sys/health') { json_response(data: { initialized: true, standby: true }, status: 429) }
      expect { client.sys.health_status }.to raise_error(Legion::Crypt::Vault::HTTPClientError) do |error|
        expect(error.code).to eq(429)
        expect(error.message).to include('429')
      end
    end

    it 'classifies proxy HTML failures as server errors, not JSON parse errors' do
      stubs.get('/v1/sys/health') { [503, { 'Content-Type' => 'text/html' }, '<html>service unavailable</html>'] }
      expect { client.sys.health_status }.to raise_error(Legion::Crypt::Vault::HTTPServerError) do |error|
        expect(error.code).to eq(503)
        expect(error.message).to include('503', 'service unavailable')
      end
    end

    it 'classifies malformed client-error bodies and does not treat raw PUT 404 as a missing read' do
      stubs.put('/v1/auth/kerberos/login') { [404, {}, 'not JSON'] }
      expect { client.put(path: 'auth/kerberos/login', body: '{}') }.to raise_error(Legion::Crypt::Vault::HTTPClientError) do |error|
        expect(error.code).to eq(404)
        expect(error.errors).to eq(['not JSON'])
      end
    end

    it 'does not follow redirects and forward Vault credentials to another origin' do
      stubs.get('/v1/secret/redirect') { [302, { 'Location' => 'https://attacker.invalid/secret' }, ''] }
      expect { client.logical.read(path: 'secret/redirect') }.to raise_error(Legion::Crypt::Vault::HTTPError) do |error|
        expect(error.code).to eq(302)
      end
      expect(connections.size).to eq(1)
    end

    it 'surfaces malformed successful responses and transport timeouts rather than returning empty secrets' do
      stubs.get('/v1/secret/invalid') { [200, {}, 'not JSON'] }
      stubs.get('/v1/secret/slow') { raise Faraday::TimeoutError, 'request timed out' }
      expect { client.logical.read(path: 'secret/invalid') }.to raise_error(Legion::JSON::ParseError)
      expect { client.logical.read(path: 'secret/slow') }.to raise_error(Faraday::TimeoutError)
    end
  end

  describe 'connection configuration and retirement' do
    let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:certificate) { certificate_for(key: private_key, common_name: 'vault.example', serial: 1) }

    it 'applies changed address, verification, and finite timeouts to subsequent requests' do
      observed = []
      stubs.get('/v1/secret/value') do |env|
        observed << [env.url.host, env.ssl.verify, env.request.open_timeout, env.request.read_timeout, env.request.write_timeout]
        json_response(data: { data: { value: 'ok' } })
      end
      client.logical.read(path: 'secret/value')
      client.address = 'https://replacement.example:8200'
      client.ssl_verify = false
      client.timeout = 2
      client.logical.read(path: 'secret/value')

      expect(observed).to eq([['vault.example', true, 5, 5, 5], ['replacement.example', false, 2, 2, 2]])
      expect(connections.first).to have_received(:close).once
    end

    it 'loads CA and mutual-TLS material from PEM and replaces obsolete trust and identity' do
      replacement_key = OpenSSL::PKey::RSA.generate(2048)
      replacement_certificate = certificate_for(key: replacement_key, common_name: 'replacement.example', serial: 2)
      observed = []
      stubs.get('/v1/sys/health') do |env|
        observed << [env.ssl.cert_store.verify(certificate), env.ssl.cert_store.verify(replacement_certificate),
                     env.ssl.client_cert.verify(private_key.public_key), env.ssl.client_cert.verify(replacement_key.public_key),
                     env.ssl.client_key.public_key.to_der]
        expect(env.ssl.verify).to be(true)
        json_response(data: { initialized: true })
      end
      client.ssl_verify = :mutual
      client.ca = certificate.to_pem
      client.cert = certificate.to_pem
      client.key = private_key.to_pem
      client.sys.health_status
      client.ca = replacement_certificate.to_pem
      client.cert = replacement_certificate.to_pem
      client.key = replacement_key.to_pem
      client.sys.health_status

      expect(observed).to eq([[true, false, true, false, private_key.public_key.to_der],
                              [false, true, false, true, replacement_key.public_key.to_der]])
      expect(connections.first).to have_received(:close).once
    end

    it 'loads client certificates and keys from paths while passing the CA path to the transport' do
      Tempfile.create(['vault-certificate', '.pem']) do |cert_file|
        Tempfile.create(['vault-key', '.pem']) do |key_file|
          cert_file.write(certificate.to_pem)
          cert_file.flush
          key_file.write(private_key.to_pem)
          key_file.flush
          client.ca = cert_file.path
          client.cert = cert_file.path
          client.key = key_file.path
          stubs.get('/v1/sys/health') do |env|
            expect(env.ssl.ca_file).to eq(cert_file.path)
            expect(env.ssl.client_cert.verify(private_key.public_key)).to be(true)
            expect(env.ssl.client_key.public_key.to_der).to eq(private_key.public_key.to_der)
            json_response(data: { initialized: true })
          end
          expect(client.sys.health_status).to be_initialized
        end
      end
    end

    it 'accepts OpenSSL identity objects without converting them into file names' do
      client.cert = certificate
      client.key = private_key
      stubs.get('/v1/sys/health') do |env|
        expect(env.ssl.client_cert.verify(private_key.public_key)).to be(true)
        signature = env.ssl.client_key.sign('SHA256', 'TLS identity')
        expect(certificate.public_key.verify('SHA256', signature, 'TLS identity')).to be(true)
        json_response(data: { initialized: true })
      end
      expect(client.sys.health_status).to be_initialized
    end

    it 'honors explicitly disabled TLS verification' do
      client.ssl_verify = :none
      stubs.get('/v1/sys/health') do |env|
        expect(env.ssl.verify).to be(false)
        json_response(data: { initialized: true })
      end
      expect(client.sys.health_status).to be_initialized
    end

    it 'rejects unbounded timeouts instead of silently disabling transport deadlines' do
      expect { described_class.new(address: address, timeout: Float::INFINITY) }.to raise_error(ArgumentError, /finite/)
      expect { client.timeout = 0 }.to raise_error(ArgumentError, /positive/)
    end

    it 'closes the transport once and prevents retained endpoint objects from reconnecting after shutdown' do
      stubs.get('/v1/secret/value') { json_response(data: { data: { value: 'ok' } }) }
      logical = client.logical
      logical.read(path: 'secret/value')
      client.shutdown
      client.shutdown
      client.address = 'https://replacement.example:8200'

      expect { logical.read(path: 'secret/value') }.to raise_error(IOError, /shut down/)
      expect { client.put(path: 'auth/token/revoke-self', body: '{}') }.to raise_error(IOError, /shut down/)
      expect(connections.size).to eq(1)
      expect(connections.first).to have_received(:close).once
    end

    it 'does not create a connection when an unused client has already been retired' do
      client.shutdown
      expect { client.sys.health_status }.to raise_error(IOError, /shut down/)
      expect(connections).to be_empty
    end
  end
end
