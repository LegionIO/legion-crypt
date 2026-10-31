# frozen_string_literal: true

require 'spec_helper'
require 'legion/crypt'

RSpec.describe Legion::Crypt::Cipher do
  before { Legion::Settings[:crypt][:cluster_secret] = Legion::Crypt.generate_secure_random }
  before { @crypt = Legion::Crypt }

  it 'can decrypt' do
    message = @crypt.encrypt('foobar')
    expect(@crypt.decrypt(message[:enciphered_message], message[:iv])).to eq 'foobar'
  end

  it 'uses a replacement settings secret instead of the previous derived key' do
    previous = @crypt.encrypt('before reload')
    configuration = Legion::Settings[:crypt].merge(cluster_secret: SecureRandom.hex(32), cs_encrypt_ready: false)
    allow(Legion::Settings).to receive(:[]).and_call_original
    allow(Legion::Settings).to receive(:[]).with(:crypt).and_return(configuration)

    current = @crypt.encrypt('after reload')
    expect(@crypt.decrypt(current[:enciphered_message], current[:iv])).to eq('after reload')
    expect do
      @crypt.decrypt(previous[:enciphered_message], previous[:iv])
    end.to raise_error(OpenSSL::Cipher::CipherError)
    expect(configuration[:cs_encrypt_ready]).to be(true)
  end

  it 'detects in-place secret changes and restores readiness after an unchanged reload' do
    previous = @crypt.encrypt('before mutation')
    Legion::Settings[:crypt][:cs_encrypt_ready] = false
    expect(@crypt.decrypt(previous[:enciphered_message], previous[:iv])).to eq('before mutation')
    expect(Legion::Settings[:crypt][:cs_encrypt_ready]).to be(true)

    Legion::Settings[:crypt][:cluster_secret].replace(SecureRandom.hex(32))
    expect do
      @crypt.decrypt(previous[:enciphered_message], previous[:iv])
    end.to raise_error(OpenSSL::Cipher::CipherError)
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

  it 'rejects truncated authentication tags even when their bytes are correct' do
    message = @crypt.encrypt('foobar')
    prefix, ciphertext, encoded_tag = message[:enciphered_message].split(':', 3)
    tag = Base64.strict_decode64(encoded_tag)

    [1, 15].each do |length|
      truncated_tag = Base64.strict_encode64(tag.byteslice(0, length))
      expect do
        @crypt.decrypt("#{prefix}:#{ciphertext}:#{truncated_tag}", message[:iv])
      end.to raise_error(ArgumentError)
    end
  end

  it 'can decrypt legacy cbc ciphertext' do
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    cipher.key = @crypt.cs
    iv = cipher.random_iv
    encrypted_message = Base64.encode64(cipher.update('legacy secret') + cipher.final)

    expect(@crypt.decrypt(encrypted_message, Base64.encode64(iv))).to eq 'legacy secret'
  end

  it 'can decrypt from keypair' do
    encrypt = @crypt.encrypt_from_keypair(message: 'test long message')
    expect(@crypt.decrypt_from_keypair(message: encrypt)).to eq 'test long message'
  end

  it 'can decrypt legacy pkcs1 keypair ciphertext' do
    encrypted_message = Base64.encode64(@crypt.private_key.public_key.public_encrypt('legacy keypair message'))

    expect(@crypt.decrypt_from_keypair(message: encrypted_message)).to eq 'legacy keypair message'
  end
end
