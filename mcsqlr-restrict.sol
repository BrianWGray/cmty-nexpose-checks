<Solution id="mcsqlr-restrict" time="2h">
  <summary>Restrict access to MC-SLQR Server Resolution Service</summary>
  <workaround>
  <p>Consider performing one or more of the following actions in order to mitigate abuse
of this service:</p>
<ol>
    <li> If there is only one SQL Server instance on this system, disable the SQL Server Browser 
service</li>
    <li> If there are multiple SQL Server instances, limit access to port 1434 UDP only to required
clients </li>
    <li> Restrict access to the MC-SLQR service to only trusted assets. </li></ol>
  </workaround>
  <AdditionalInfo>
    <p>If the SQL Server is not needed, consider disabling or uninstalling the service entirely. </p>
  </AdditionalInfo>
</Solution>
