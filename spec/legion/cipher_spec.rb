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

  it 'rejects tampered authenticated ciphertext' do
    message = @crypt.encrypt('foobar')
    prefix, ciphertext, auth_tag = message[:enciphered_message].split(':', 3)
    decoded_auth_tag = Base64.strict_decode64(auth_tag).bytes
    decoded_auth_tag[-1] ^= 0x01
    tampered_auth_tag = Base64.strict_encode64(decoded_auth_tag.pack('C*'))

    expect do
      @crypt.decrypt("#{prefix}:#{ciphertext}:#{tampered_auth_tag}", message[:iv])
    end.to raise_error(OpenSSL::Cipher::CipherError)
  end

  it 'can decrypt legacy cbc ciphertext' do
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    cipher.key = @crypt.cs
    iv = cipher.random_iv
    encrypted_message = Base64.encode64(cipher.update('legacy secret') + cipher.final)

    expect(@crypt.decrypt(encrypted_message, Base64.encode64(iv))).to eq 'legacy secret'
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
