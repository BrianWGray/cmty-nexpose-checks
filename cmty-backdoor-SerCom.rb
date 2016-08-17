#!/usr/bin/env ruby
# Brian W. Gray
# 09.22.2014

# Creates test http server that emulated a vulnerable SerCom backdoor response.
require 'socket'

server = TCPServer.new 32764
puts "Test server listening\r\n\r\n"

response = "ScMM\xFF\xFF\xFF\xFF\x00\x00\x00\x00"

loop do
    
    client = server.accept
    request = client.gets
    STDERR.puts request
    client.puts response
    client.close
    
end