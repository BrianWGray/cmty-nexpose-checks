<Solution id="cmty-x11-putty-access" time="30m">
  <summary>Forwarding X11 through SSH via PuTTy</summary>
  <AppliesTo>
    <OS family="Windows"/>
  </AppliesTo>
  <workaround>
    <p>
      PuTTy:
      <ul>
        <li>1.) Run &#34;PuTTY&#34; found in the &#34;X-Win32&#34; program group of the &#34;Start&#34; menu.</li>
        <li>2.) Enter the desired remote hostname in the &#34;Host Name (or IP address)&#34; box</li>
        <li>3.) Click the &#34;SSH&#34; category from the left pane</li>
        <li>4.) Under &#34;Preferred SSH Protocol Version&#34;, select &#34;2 only&#34;</li>
        <li>5.) Click the &#34;Tunnels&#34; sub-category under &#34;SSH&#34; in the left pane</li>
        <li>6.) Checkmark &#34;Enable X11 forwarding&#34; at the top.</li>
        <li>7.) Click the &#34;Session&#34; category from the left pane.</li>
        <li>8.) Enter a meaningful name in the &#34;Saved Sessions&#34; box.</li>
        <li>9.) Click the &#34;Save&#34; button.</li>
        <li>10.) Repeat steps 1 through 9 for other remote hosts that you routinely use.</li>
      </ul>
    </p>
  </workaround>
</Solution>
