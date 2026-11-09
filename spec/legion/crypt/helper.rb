# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Crypt::Helper do
  let(:helper_class) do
    Class.new do
      include Legion::Crypt::Helper

      def lex_filename
        'microsoft_teams'
      end
    end
  end

  let(:bare_class) do
    stub_const('Legion::Extensions::MyExtension::Runners::Foo', Class.new do
      include Legion::Crypt::Helper
    end)
  end

  subject { helper_class.new }

  describe '#vault_namespace' do
    it 'derives from lex_filename' do
      expect(subject.vault_namespace).to eq('microsoft_teams')
    end

    it 'derives from class name when lex_filename is not defined' do
      obj = bare_class.new
      expect(obj.vault_namespace).to eq('my_extension')
    end
  end

  describe '#vault_get' do
    it 'delegates to Legion::Crypt.get with namespace' do
      expect(Legion::Crypt).to receive(:get).with('microsoft_teams').and_return({ token: 'abc' })
      expect(subject.vault_get).to eq({ token: 'abc' })
    end

    it 'appends suffix to namespace' do
      expect(Legion::Crypt).to receive(:get).with('microsoft_teams/auth').and_return({ token: 'abc' })
      expect(subject.vault_get('auth')).to eq({ token: 'abc' })
    end
  end

  describe '#vault_write' do
    it 'delegates to Legion::Crypt.write with namespace' do
      expect(Legion::Crypt).to receive(:write).with('microsoft_teams/auth', token: 'abc')
      subject.vault_write('auth', token: 'abc')
    end
  end

  describe '#vault_exist?' do
    it 'delegates to Legion::Crypt.exist? with namespace' do
      expect(Legion::Crypt).to receive(:exist?).with('microsoft_teams').and_return(true)
      expect(subject.vault_exist?).to be true
    end

    it 'appends suffix to namespace' do
      expect(Legion::Crypt).to receive(:exist?).with('microsoft_teams/auth').and_return(false)
      expect(subject.vault_exist?('auth')).to be false
    end
  end
end
