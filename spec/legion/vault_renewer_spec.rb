# frozen_string_literal: true

# # require 'spec_helper'
# #
# require 'legion/extensions/helpers/core'
# require 'legion/extensions/helpers/logger'
# require 'legion/extensions/helpers/lex'
# require 'legion/extensions/actors/every'
# require 'legion/crypt/vault_renewer'
#
# RSpec.describe Legion::Crypt::Vault::Renewer do
#   it 'can init' do
#     expect { Legion::Crypt::Vault::Renewer.new }.not_to raise_exception
#   end
#
#   before do
#     @renewer = Legion::Crypt::Vault::Renewer.new
#   end
#   it 'is an actor' do
#     expect(@renewer).to be_a Legion::Extensions::Actors::Every
#   end
#
#   it 'has settings set for the actor' do
#     expect(@renewer.runner_function).to eq 'renew_sessions'
#     expect(@renewer.class).to eq Legion::Crypt::Vault::Renewer
#     expect(@renewer.time).to eq 5
#     expect(@renewer.use_runner?).to eq false
#   end
#
#   it 'can cancel' do
#     expect { @renewer.cancel }.not_to raise_exception
#   end
#
#   it '.generate_task?' do
#     expect(@renewer.generate_task?).to eq false
#   end
#
#   it '.check_subtask?' do
#     expect(@renewer.check_subtask?).to eq false
#   end
#
#   it 'uses the correct class' do
#     expect(@renewer.runner_class).to eq Legion::Crypt
#   end
# end
