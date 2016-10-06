#!/usr/bin/env ruby
# Brian W. Gray
# 08.28.2014

# Creates test http server that emulated the important bits of OWA to test signatures against.

require 'socket'
require 'cgi'


server = TCPServer.new 80
puts "Test server listening\r\n\r\n"

#response = "Hi"
response = "<link rel=\"shortcut icon\" href=\"/owa/auth/15.0.1178/themes/resources/favicon.ico\" type=\"image/x-icon\">"

loop do
    
    client = server.accept
    request = client.gets
    STDERR.puts request
    time = CGI.rfc1123_date(Time.now)    
    headers = ["http/1.1 200 ok",
    "#{time}",
    "Server: Microsoft-IIS/8.5",
    "Vary: Accept-Encoding",
    "content-type: text/html;, #{} charset=\"UTF-8\"",
    "content-length: #{response.bytesize}",
    "Connection: close\r\n\r\n"].join("\r\n")
    client.puts headers
    client.puts response # .encode('utf-8')
    client.close
end
