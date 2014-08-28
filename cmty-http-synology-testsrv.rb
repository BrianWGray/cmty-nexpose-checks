require 'socket'
require 'cgi'



server = TCPServer.new 5000
puts "Test server listening\r\n\r\n"

response = "<html> <script type='text/javascript'>parent.location = '#major=4&minor=2&build=3211&junior=0&unique=synology_cedarview_rs2212+&sn=D4LFN00210'</script> </html>"


loop do
    
    client = server.accept
    
    request = client.gets
    
    STDERR.puts request
    
    time = CGI.rfc1123_date(Time.now)
    
    headers = ["http/1.1 200 ok",
    "#{time}",
    "Server: Apache/2.2.23 (Unix) mod_ssl/2.2.23 OpenSSL/1.0.1e-fips",
    "Vary: Accept-Encoding",
    "content-type: text/html; charset=\"UTF-8\"",
    "content-length: #{response.bytesize}",
    "Connection: close\r\n\r\n"].join("\r\n")
    client.puts headers
    client.puts response
    client.close
end