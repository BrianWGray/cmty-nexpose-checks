<?xml version="1.0" encoding="UTF-8"?>
<Solution id="cmty-apache-disable-default-open-proxy" time="1h00m">
      <summary>Configure access controls for mod_proxy</summary>
      <AppliesTo>
        <Product name="apache"/>
      </AppliesTo>
      <workaround>
        <p>
                If you don't need to run a proxy server, disable mod_proxy by commenting out its LoadModule line or setting ProxyRequests off in httpd.conf. Remember that disabling ProxyRequests does not prevent you from using a reverse proxy with the ProxyPass directive.

                If you do need to have Apache act as a proxy server, be sure to <a href="http://httpd.apache.org/docs/trunk/mod/mod_proxy.html#access">secure your server</a> by restricting access with a Proxy section in httpd.conf.
               
                An access control list (ACL) should be defined for the apache mod_proxy server
                in the file: <pre>httpd.conf</pre>

            </p>
      </workaround>
    </Solution>