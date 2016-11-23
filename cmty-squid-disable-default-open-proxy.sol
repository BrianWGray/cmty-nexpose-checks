<?xml version="1.0" encoding="UTF-8"?>
<Solution id="cmty-squid-disable-default-open-proxy" time="1h00m">
      <summary>Disable the squid default open HTTP proxy</summary>
      <AppliesTo>
        <Product name="squid"/>
      </AppliesTo>
      <workaround>
        <p>
               An access control list (ACL) should be defined for the squid proxy server
               in the file: <pre>squid.conf</pre>
            </p>
            <p>
               Consult the Squid 3.0 configuration manual, located at the
               <a href="http://www.visolve.com/squid/squid30/contents.php">ViSolve</a> website.
            </p>
      </workaround>
    </Solution>