<Solution id="cmty-x11-xwin32-access" time="30m">
  <summary>X-Win32 Solution for restricting access to localhost</summary>
  <AppliesTo>
    <OS family="Windows"/>
  </AppliesTo>
  <workaround>
    <p>
      Configure X-Win32 to only allow connections from your local computer:
      <ul>
        <li>1.) Run &#34;X-Config&#34; found in the &#34;X-Win32&#34; program group of the &#34;Start&#34; menu.</li>
        <li>2.) Click on the &#34;Security&#34; tab.</li>
        <li>3.) Click the &#34;Add&#34; button to the right of the &#34;X-Host&#34; list.</li>
        <li>4.) Type &#34;127.0.0.1&#34; (without the quotes) in the box that appears and click &#34;OK&#34;.</li>
        <li>5.) Checkmark the &#34;Access Control&#34; box Click the &#34;OK&#34; button to close &#34;X-Config&#34;.
Note: If you have X-Win32 already running, you will need to restart it for the X-Config changes to take effect.</li>
        <li>6.) Configure SSH X11 forwarding to encrypt communication with the remote computers.
Note: The exact steps vary based on which SSH client you are using.</li>
      </ul>
      launch X Windows applications:    
      <ul>
        <li>1.) Run &#34;X-Win32&#34; from the &#34;Start&#34; menu.</li>
        <li>2.) Connect to the desired remote host using the saved Session (PuTTY) or Profile (Secure Shell SSH) from your preferred SSH client.</li>
        <li>3.) Launch your desired X Windows application from the new terminal session by typing the application executable name followed by an &#34;&#38;&#34;, for instance &#34;xterm &#38;&#34; (without the quotes.)</li>
      </ul>
    </p>
  </workaround>
</Solution>