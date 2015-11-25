function reddit_client() {
  var processActiveAuthResponse = function(client) {
    if (sessionStatusRequest.readyState == 4 ) {
      if (sessionStatusRequest.status == 200) {
        jsonResponse = JSON.parse(sessionStatusRequest.responseText)
        client.sessionId = jsonResponse.session_id
        client.sessionStatus = jsonResponse.session_status
        client.token = jsonResponse.token
        client.tokenExpiration = Math.floor(Date.now() / 1000) + parseInt(jsonResponse.token_expires_in)
      }
    }
  };
  var sessionStatusRequest = new XMLHttpRequest();
  sessionStatusRequest.onreadystatechange = processActiveAuthResponse(this);
  xhttp.open("GET", "{{ app_url }}/auth/active", false);
  xhttp.setRequestHeader("User-Agent", "{{ user_agent }}");
  xhttp.send();

  // cookies were refreshed in the above request if it passed,
  // so the session_expires_in is valid now
  var sessionExpirationCookie = "session_expires_in=";
  var allCookies = document.cookie.split(';');
  for(var i=0; i<allCookies.length; i++) {
    var cookie = allCookies[i];
    while (cookie.charAt(0)==' ') cookie = cookie.substring(1);
    if (cookie.indexOf(sessionExpirationCookie) == 0)
      this.sessionExpiration = Math.floor(Date.now() / 1000) + parseInt(cookie.substring(sessionExpirationCookie.length,cookie.length));
  }

}
