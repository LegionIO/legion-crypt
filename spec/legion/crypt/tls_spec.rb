# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt/tls'

RSpec.describe Legion::Crypt::TLS do
  describe '.resolve' do
    it 'returns all defaults with empty config' do
      result = described_class.resolve({})
      expect(result[:enabled]).to be false
      expect(result[:verify]).to eq :peer
      expect(result[:ca]).to be_nil
      expect(result[:cert]).to be_nil
      expect(result[:key]).to be_nil
      expect(result[:auto_detected]).to be false
    end

    it 'returns enabled when explicitly set' do
      result = described_class.resolve({ enabled: true })
      expect(result[:enabled]).to be true
    end

    it 'normalizes string verify to symbol' do
      result = described_class.resolve({ verify: 'mutual', cert: '/tmp/c.crt', key: '/tmp/k.key' })
      expect(result[:verify]).to eq :mutual
    end

    it 'normalizes string keys to symbols' do
      result = described_class.resolve({ 'enabled' => true, 'verify' => 'none' })
      expect(result[:enabled]).to be true
      expect(result[:verify]).to eq :none
    end

    it 'passes through file paths unchanged' do
      result = described_class.resolve({
                                         ca:   '/etc/ssl/ca.crt',
                                         cert: '/etc/ssl/client.crt',
                                         key:  '/etc/ssl/client.key'
                                       })
      expect(result[:ca]).to eq '/etc/ssl/ca.crt'
      expect(result[:cert]).to eq '/etc/ssl/client.crt'
      expect(result[:key]).to eq '/etc/ssl/client.key'
    end
  end

  describe 'port auto-detection' do
    it 'auto-enables for AMQPS port 5671' do
      result = described_class.resolve({}, port: 5671)
      expect(result[:enabled]).to be true
      expect(result[:auto_detected]).to be true
    end

    it 'auto-enables for Redis TLS port 6380' do
      result = described_class.resolve({}, port: 6380)
      expect(result[:enabled]).to be true
      expect(result[:auto_detected]).to be true
    end

    it 'auto-enables for Memcached TLS port 11207' do
      result = described_class.resolve({}, port: 11_207)
      expect(result[:enabled]).to be true
      expect(result[:auto_detected]).to be true
    end

    it 'does not auto-enable for unknown port' do
      result = described_class.resolve({}, port: 5432)
      expect(result[:enabled]).to be false
      expect(result[:auto_detected]).to be false
    end

    it 'respects explicit enabled: false even on TLS port' do
      result = described_class.resolve({ enabled: false }, port: 5671)
      expect(result[:enabled]).to be false
      expect(result[:auto_detected]).to be false
    end
  end

  describe 'mutual TLS validation' do
    it 'downgrades mutual to peer when cert is missing' do
      result = described_class.resolve({ verify: 'mutual', key: '/tmp/k.key' })
      expect(result[:verify]).to eq :peer
    end

    it 'downgrades mutual to peer when key is missing' do
      result = described_class.resolve({ verify: 'mutual', cert: '/tmp/c.crt' })
      expect(result[:verify]).to eq :peer
    end

    it 'keeps mutual when both cert and key are present' do
      result = described_class.resolve({
                                         verify: 'mutual',
                                         cert:   '/tmp/c.crt',
                                         key:    '/tmp/k.key'
                                       })
      expect(result[:verify]).to eq :mutual
    end
  end

  describe '.migrate_legacy' do
    it 'maps legacy transport keys to standard shape' do
      legacy = {
        use_tls:     true,
        verify_peer: true,
        ca_certs:    '/etc/ca.crt',
        tls_cert:    '/etc/client.crt',
        tls_key:     '/etc/client.key'
      }
      result = described_class.migrate_legacy(legacy)
      expect(result[:enabled]).to be true
      expect(result[:verify]).to eq 'peer'
      expect(result[:ca]).to eq '/etc/ca.crt'
      expect(result[:cert]).to eq '/etc/client.crt'
      expect(result[:key]).to eq '/etc/client.key'
    end

    it 'passes through standard config unchanged' do
      standard = { enabled: true, verify: 'peer' }
      result = described_class.migrate_legacy(standard)
      expect(result).to eq standard
    end

    it 'maps verify_peer false to none' do
      legacy = { use_tls: true, verify_peer: false }
      result = described_class.migrate_legacy(legacy)
      expect(result[:verify]).to eq 'none'
    end
  end

  describe 'vault URI resolution' do
    it 'resolves vault:// URIs when resolver is available' do
      resolver = class_double('Legion::Settings::Resolver')
      stub_const('Legion::Settings::Resolver', resolver)
      allow(resolver).to receive(:resolve_value).with('vault://pki/issue/legion#certificate').and_return('/tmp/resolved.crt')
      allow(resolver).to receive(:resolve_value).with('/tmp/ca.crt').and_return('/tmp/ca.crt')
      allow(resolver).to receive(:resolve_value).with('/tmp/k.key').and_return('/tmp/k.key')

      result = described_class.resolve({
                                         ca:   '/tmp/ca.crt',
                                         cert: 'vault://pki/issue/legion#certificate',
                                         key:  '/tmp/k.key'
                                       })
      expect(result[:cert]).to eq '/tmp/resolved.crt'
    end

    it 'passes through when resolver is not available' do
      result = described_class.resolve({ ca: 'vault://pki/ca' })
      expect(result[:ca]).to eq 'vault://pki/ca'
    end
  end

  describe 'TLS_PORTS' do
    it 'contains AMQPS, Redis TLS, and Memcached TLS' do
      expect(described_class::TLS_PORTS).to include(5671, 6380, 11_207)
    end
  end

  describe 'default settings' do
    it 'provides tls defaults in crypt settings' do
      defaults = Legion::Crypt::Settings.default
      expect(defaults[:tls]).to be_a(Hash)
      expect(defaults[:tls][:enabled]).to be false
      expect(defaults[:tls][:verify]).to eq 'peer'
    end
  end
end
