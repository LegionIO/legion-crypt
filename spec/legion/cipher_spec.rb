# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt'

RSpec.describe Legion::Crypt::Cipher do
  before { Legion::Settings[:crypt][:cluster_secret] = Legion::Crypt.generate_secure_random }
  before { @crypt = Legion::Crypt }
  before { @crypt.start }

  it 'can encrypt' do
    expect(@crypt.encrypt('test')).to be_a Hash
    expect(@crypt.encrypt('test')).to have_key :enciphered_message
    expect(@crypt.encrypt('test')).to have_key :iv
  end

  it 'can decrypt' do
    message = @crypt.encrypt('foobar')
    expect(@crypt.decrypt(message[:enciphered_message], message[:iv])).to eq 'foobar'
  end

  it 'can encrypt from keypair' do
    expect(@crypt.private_key).to be_a OpenSSL::PKey::RSA
    expect(@crypt.public_key).to be_a String
    expect(Base64.encode64(@crypt.private_key.public_key.to_s)).to be_a String
    expect(@crypt.encrypt_from_keypair(message: 'test')).to be_a String
    expect(@crypt.encrypt_from_keypair(message: 'test', pub_key: @crypt.public_key)).to be_a String
  end

  it 'can decrypt from keypair' do
    encrypt = @crypt.encrypt_from_keypair(message: 'test long message')
    expect(@crypt.decrypt_from_keypair(message: encrypt)).to eq 'test long message'
  end
end
