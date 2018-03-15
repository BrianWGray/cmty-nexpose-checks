<Solution id="cmty-x11-unix-access" time="30m">
  <summary>UNIX Solution for disabling open access to X11</summary>
  <workaround>
    <p>
      Implement one or more of:
      <ul>
        <li>Disable X11 from listening on TCP ports</li>
        <li>Firewall X11&#39;s TCP ports</li>
        <li>Restrict access using <pre>xhost -</pre></li>
      </ul>
    </p>
  </workaround>
</Solution>