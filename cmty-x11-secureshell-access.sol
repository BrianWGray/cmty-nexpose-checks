<Solution id="cmty-x11-secureshell-access" time="30m">
  <summary>Forwarding X11 through SSH via SSH Secure Shell</summary>
  <workaround>
    <p>
      SSH Secure Shell:
      <ul>
        <li>1.) Run &#34;Secure Shell Client&#34; found in the &#34;SSH Secure Shell&#34; program group of the &#34;Start&#34; menu.</li>
        <li>2.) From the &#34;File&#34; menu, choose &#34;Profiles&#34; and then &#34;Add Profile...</li>
        <li>3.) In the &#34;Add Profile&#34; box, type a meaningful name and click &#34;Add to Profiles&#34;.</li>
        <li>4.) From the &#34;File&#34; menu, choose &#34;Profiles&#34; and then &#34;Edit Profile...&#34;</li>
        <li>5.) Click the meaningful name of the profile you just created from the list on the left.</li>
        <li>6.) Click the &#34;Connection&#34; tab.</li>
        <li>7.) Enter the desired remote hostname in the &#34;Host name:&#34; box.</li>
        <li>8.) Enter your username on the remote system in the &#34;User name:&#34; box.</li>
        <li>9.) Click &#34;OK&#34; to confirm the changes.</li>
        <li>10.) From the &#34;File&#34; menu, choose &#34;Profiles&#34; and then &#34;Edit Profile...&#34;</li>
        <li>11.) Click the meaningful name of the profile you just created from the list on the left.</li>
        <li>12.) Click the &#34;Tunneling&#34; tab.</li>
        <li>13.) Checkmark &#34;Tunnel X11 connections&#34;.</li>
        <li>14.) Click &#34;OK&#34; to confirm the changes.</li>
        <li>15.) From the &#34;File&#34; menu, choose &#34;Save Settings&#34; to save the changes permanently.</li>
        <li>16.) Repeat steps 1 through 15 for other remote hosts that you routinely use.</li>
      </ul>
    </p>
  </workaround>
</Solution>