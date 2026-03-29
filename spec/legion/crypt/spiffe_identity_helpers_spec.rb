# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'legion/crypt/spiffe'
require 'legion/crypt/spiffe/workload_api_client'
require 'legion/crypt/spiffe/identity_helpers'

RSpec.describe Legion::Crypt::Spiffe::IdentityHelpers do
  # Mix helpers into an anonymous object for testing.
  let(:helper) { Object.new.extend(described_class) }

  # Build a real self-signed EC cert + key for signing/verification tests.
  let(:ec_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:cert) do
    c = OpenSSL::X509::Certificate.new
    c.version    = 2
    c.serial     = OpenSSL::BN.rand(64)
    c.not_before = Time.now - 1
    c.not_after  = Time.now + 3600
    spiffe_uri = 'spiffe://test.local/workload/helper-test'
    c.subject  = OpenSSL::X509::Name.parse("/CN=#{spiffe_uri}")
    c.issuer   = c.subject
    c.public_key = ec_key
    ext_factory = OpenSSL::X509::ExtensionFactory.new(c, c)
    c.add_extension(ext_factory.create_extension('subjectAltName', "URI:#{spiffe_uri}", false))
    c.add_extension(ext_factory.create_extension('basicConstraints', 'CA:FALSE', true))
    c.sign(ec_key, OpenSSL::Digest.new('SHA256'))
    c
  end

  let(:spiffe_id) { Legion::Crypt::Spiffe.parse_id('spiffe://test.local/workload/helper-test') }
  let(:live_svid) do
    Legion::Crypt::Spiffe::X509Svid.new(
      spiffe_id,
      cert.to_pem,
      ec_key.private_to_pem,
      nil,
      cert.not_after
    )
  end
  let(:expired_svid) do
    Legion::Crypt::Spiffe::X509Svid.new(
      spiffe_id,
      cert.to_pem,
      ec_key.private_to_pem,
      nil,
      Time.now - 1
    )
  end

  describe '#sign_with_svid' do
    it 'returns a Base64-encoded string' do
      sig = helper.sign_with_svid('hello world', svid: live_svid)
      expect(sig).to be_a(String)
      expect { Base64.strict_decode64(sig) }.not_to raise_error
    end

    it 'raises SvidError when svid is nil' do
      expect { helper.sign_with_svid('data', svid: nil) }
        .to raise_error(Legion::Crypt::Spiffe::SvidError, /nil/)
    end

    it 'raises SvidError when svid is expired' do
      expect { helper.sign_with_svid('data', svid: expired_svid) }
        .to raise_error(Legion::Crypt::Spiffe::SvidError, /expired/)
    end
  end

  describe '#verify_svid_signature' do
    let(:data) { 'the data to sign' }
    let(:signature_b64) { helper.sign_with_svid(data, svid: live_svid) }

    it 'returns true for a valid signature' do
      expect(helper.verify_svid_signature(data, signature_b64: signature_b64, svid: live_svid)).to be true
    end

    it 'returns false for a tampered payload' do
      expect(helper.verify_svid_signature('tampered', signature_b64: signature_b64, svid: live_svid)).to be false
    end

    it 'returns false for a corrupted signature' do
      bad_sig = Base64.strict_encode64('not-a-real-sig')
      expect(helper.verify_svid_signature(data, signature_b64: bad_sig, svid: live_svid)).to be false
    end

    it 'raises SvidError when svid is nil' do
      expect { helper.verify_svid_signature(data, signature_b64: 'x', svid: nil) }
        .to raise_error(Legion::Crypt::Spiffe::SvidError, /nil/)
    end

    it 'raises SvidError when svid is expired' do
      expect { helper.verify_svid_signature(data, signature_b64: 'x', svid: expired_svid) }
        .to raise_error(Legion::Crypt::Spiffe::SvidError, /expired/)
    end
  end

  describe '#extract_spiffe_id_from_cert' do
    it 'extracts the SPIFFE ID from the SAN URI extension' do
      id = helper.extract_spiffe_id_from_cert(cert.to_pem)
      expect(id).not_to be_nil
      expect(id.trust_domain).to eq('test.local')
      expect(id.path).to eq('/workload/helper-test')
    end

    it 'returns nil for a cert without a SPIFFE SAN' do
      plain_key  = OpenSSL::PKey::EC.generate('prime256v1')
      plain_cert = OpenSSL::X509::Certificate.new
      plain_cert.subject    = OpenSSL::X509::Name.parse('/CN=plain')
      plain_cert.issuer     = plain_cert.subject
      plain_cert.not_before = Time.now - 1
      plain_cert.not_after  = Time.now + 3600
      plain_cert.public_key = plain_key
      plain_cert.sign(plain_key, OpenSSL::Digest.new('SHA256'))

      expect(helper.extract_spiffe_id_from_cert(plain_cert.to_pem)).to be_nil
    end

    it 'returns nil for invalid PEM input' do
      expect(helper.extract_spiffe_id_from_cert('not-a-cert')).to be_nil
    end
  end

  describe '#trusted_cert?' do
    it 'raises SvidError when svid is nil' do
      expect { helper.trusted_cert?(cert.to_pem, svid: nil) }
        .to raise_error(Legion::Crypt::Spiffe::SvidError, /nil/)
    end

    it 'returns false when svid has no bundle' do
      svid = Legion::Crypt::Spiffe::X509Svid.new(spiffe_id, cert.to_pem, ec_key.private_to_pem, nil, Time.now + 3600)
      expect(helper.trusted_cert?(cert.to_pem, svid: svid)).to be false
    end

    it 'returns true when the leaf cert is signed by the bundle CA' do
      # Use the self-signed cert as both leaf and bundle (self-signed trusts itself).
      svid = Legion::Crypt::Spiffe::X509Svid.new(spiffe_id, cert.to_pem, ec_key.private_to_pem, cert.to_pem, Time.now + 3600)
      expect(helper.trusted_cert?(cert.to_pem, svid: svid)).to be true
    end
  end

  describe '#svid_identity' do
    it 'returns an empty hash for nil' do
      expect(helper.svid_identity(nil)).to eq({})
    end

    it 'returns type :x509 for an X509Svid' do
      identity = helper.svid_identity(live_svid)
      expect(identity[:type]).to eq(:x509)
      expect(identity[:spiffe_id]).to eq('spiffe://test.local/workload/helper-test')
      expect(identity[:trust_domain]).to eq('test.local')
      expect(identity[:workload_path]).to eq('/workload/helper-test')
      expect(identity[:expired]).to be false
      expect(identity[:ttl_seconds]).to be_a(Integer)
    end

    it 'returns type :jwt for a JwtSvid' do
      jwt_svid = Legion::Crypt::Spiffe::JwtSvid.new(spiffe_id, 'tok', 'myservice', Time.now + 3600)
      identity = helper.svid_identity(jwt_svid)
      expect(identity[:type]).to eq(:jwt)
      expect(identity[:audience]).to eq('myservice')
    end
  end
end
