require 'socket'
require 'cgi'


htmlReply = "<html> <script type='text/javascript'>parent.location = '#major=4&minor=2&build=3211&junior=0&unique=synology_cedarview_rs2212+&sn=D4LFN00210'</script> </html>"


server = TCPServer.open 5000
puts "Test server listening on port 5000\r\n\r\n"

loop {
    client = server.accept
    
    lines = []
    while line = client.gets and line !~ /^\s*$/
        lines << line.chomp
    end
    
    time = CGI.rfc1123_date(Time.now)
    
    resp = lines.join("<br />")
    headers = ["http/1.1 200 ok",
    time,
    "Server: Apache/2.2.23 (Unix) mod_ssl/2.2.23 OpenSSL/1.0.1e-fips",
    "Vary: Accept-Encoding",
    "content-type: text/html; charset=iso-8859-1",
    "content-length: #{resp.length}\r\n\r\n"].join("\r\n")
    client.puts htmlReply
    client.close
    puts headers
    puts "Request: #{resp} \r\n\r\n"
    puts "Reply: #{htmlReply} \r\n\r\n"
}