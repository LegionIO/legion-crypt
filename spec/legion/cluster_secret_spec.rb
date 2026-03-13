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
    expect(@cs.force_cluster_secret).to eq true
  end

  it '.settings_push_vault' do
    expect(@cs.settings_push_vault).to eq true
  end

  it '.only_member?' do
    expect(@cs.only_member?).to eq nil
  end

  it '.push_cs_to_vault' do
    expect(@cs.push_cs_to_vault).to eq false
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
end
