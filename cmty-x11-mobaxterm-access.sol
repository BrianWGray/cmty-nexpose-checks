<Solution id="cmty-x11-mobaxterm-access" time="30m">
  <summary>MobaXterm Solution for restricting access to localhost</summary>
  <AppliesTo>
    <OS family="Windows"/>
  </AppliesTo>
  <workaround>
    <p>
      Configure MobaXterm for Windows to only allow connections from your local computer:
      <ul>
        <li>1.) Start MobaXterm.</li>
        <li>2.) Under Settings, click Configuration.</li>
        <li>3.) In the MobaXterm Configuration window, click on the &#34;X11&#34; tab. </li>
        <li>4.) In the center panel, locate &#34;X11 remote access&#34;. </li>
        <li>5.) Use the drop-down beside &#34;X11 remote access&#34; and select &#34;disabled&#34;.</li>
        <li>6.) Click &#34;OK&#34; to save your changes.</li>
      </ul>
      launch X Windows applications:    
      <ul>
        <li>1.) Run &#34;MobaXterm&#34; from the &#34;Start&#34; menu.</li>
        <li>2.) Connect to the desired remote host using the saved Session (PuTTY) or Profile (Secure Shell SSH) from your preferred SSH client.</li>
        <li>3.) Launch your desired X Windows application from the new terminal session by typing the application executable name followed by an &#34;&#38;&#34;, for instance &#34;xterm &#38;&#34; (without the quotes.)</li>
      </ul>
    </p>
  </workaround>
</Solution>