# frozen_string_literal: true

require 'socket'
require 'timeout'
require 'legion/logging'
Legion::Logging.setup(level: :fatal)
require 'legion/crypt'
require 'legion/extensions/helpers/lex'
require 'legion/crypt/vault/renewer'

scenario = ARGV.fetch(0)
raise ArgumentError, 'Unknown renewal scenario' unless %w[renew cancel].include?(scenario)

listener = worker = actor = timer = nil
requests = []

begin
  Timeout.timeout(10) do
    configuration = Legion::Crypt::Settings.default
    configuration[:vault].merge!(token: nil, clusters: {}, vault_namespace: nil)
    listener = TCPServer.new('127.0.0.1', 0)
    configuration[:vault].merge!(address: '127.0.0.1', port: listener.addr[1])
    if scenario == 'renew'
      worker = Thread.new do
        2.times do
          socket = listener.accept
          begin
            method, path = socket.gets.split
            headers = {}
            while (line = socket.gets) && line != "\r\n"
              name, value = line.split(':', 2)
              headers[name.downcase] = value.strip
            end
            data = Legion::JSON.load(socket.read(Integer(headers.fetch('content-length'))))
            requests << { method: method, path: path, lease_id: data[:lease_id] }
            body = Legion::JSON.dump({ lease_id: data[:lease_id], lease_duration: 3600, renewable: true, data: {} })
            socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
          ensure
            socket.close
          end
        end
      end
    end
    Legion::Settings.set_prop(:crypt, configuration)
    Legion::Crypt.start_session_tracking
    Legion::Crypt.add_session(path: 'lease/first')
    Legion::Crypt.add_session(path: 'lease/second')

    actor = Legion::Crypt::Vault::Renewer.new
    timer = actor.instance_variable_get(:@timer)
    worker&.value
    actor.cancel
    terminated = timer.wait_for_termination(1)

    result = { requests: requests, sessions: Legion::Crypt.sessions, terminated: terminated, running: timer.running? }
    puts "RENEWER_RESULT=#{Legion::JSON.dump(result)}"
  end
ensure
  actor&.cancel
  timer&.wait_for_termination(1)
  worker&.kill
  worker&.join
  listener&.close
  Legion::Crypt.clear_vault_clients
end
