<Solution id="cmty-disable-simpletcpservices" time="15m">
  <summary>Disable Simple TCP/IP Services on Windows</summary>
  <AppliesTo>
    <OS family="Windows"/>
  </AppliesTo>
  <workaround>
    <p>A common reason for this listener on Microsoft Windows is due to the Simple TCP/IP Services being enabled. Simple TCP/IP Services, supports the following services: Character Generator, Daytime, Discard, Echo, and Quote of the Day. Consider performing the following actions in order to mitigate abuse of this service:</p>
    <p>To determine whether this service is running you will need to check the running features/services as follows:
      <ol>
        <li>Start>Control Panel>"Turn Windows features on or off" (on the left hand sidebar) This will open a small dialog box listing services.</li>
        <li>You should see "Simple TCP/IP services (i.e. echo, daytime etc)" in the list. If the box beside it is checked, the services have been installed.</li>
        <li>To uninstall them, click to remove the check from the box.</li>
        <li>You may have to reboot the system in order for this to take effect.</li>
      </ol></p>
  </workaround>
  <AdditionalInfo>
    <p>If the service is required consider restricting access to the service to only source from trusted assets.</p>
  </AdditionalInfo>
</Solution>