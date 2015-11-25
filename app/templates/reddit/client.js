function RedditClient() {
  // extracts the value of a cookie with given name
  var getCookie = function(cookieName) {
    var cookieIdentifier = cookieName + '=';
    var allCookies = document.cookie.split(';');
    for(var i=0; i<allCookies.length; i++) {
      var cookie = allCookies[i];
      while (cookie.charAt(0)==' ')
        cookie = cookie.substring(1);
      if (cookie.indexOf(cookieIdentifier) == 0)
        return cookie.substring(cookieIdentifier.length, cookie.length));
    }
  }

  // poll <app_url>/auth/active to let the backend know that the client is active
  // it also requests a new bearer token if the old one has already expired
  // this should be called periodically to keep the login session alive
  this.refresh = function() {
    var processActiveAuthResponse = function(client) {
      if (sessionStatusRequest.readyState == 4 ) {
        if (sessionStatusRequest.status == 200) {
          jsonResponse = JSON.parse(sessionStatusRequest.responseText)
          client.sessionId = jsonResponse.session_id
          client.sessionStatus = jsonResponse.session_status
          client.token = jsonResponse.token
          client.tokenExpiration = Date.now() + 1000*parseInt(jsonResponse.token_expires_in)
        }
        else if (sessionStatusRequest.status != 500)
          throw { 'code': sessionStatusRequest.status,
                  'message': JSON.parse(sessionStatusRequest.responseText).error }
        else
          throw { 'code': 500, 'message': 'internal server error' }
      }
    };
    var sessionStatusRequest = new XMLHttpRequest();
    sessionStatusRequest.onreadystatechange = processActiveAuthResponse(super);
    xhttp.open("GET", "{{ app_url }}/auth/active", false);
    xhttp.setRequestHeader("User-Agent", "{{ user_agent }}");
    xhttp.send();

    // cookies were refreshed in the above request to the <app>/auth/active URL
    // so the "session_expires_in" cookie value is now valid
    this.sessionExpiration = Date.now() + 1000*parseInt(getCookie('session_expires_in')));
  }
  
  // registers a new callback function that will be called after query
  // intended use is this:
  //     processQueryResult = new redditClientInstance.call(myResultProcessingFunction)
  //     processQueryResult.after('GET', '/api/v1/me')
  // the parameters are the callback function
  // and error processing function, which will be called if the API request fails
  // the error processing function can be omitted
  this.call = function(resultProcessor, errorProcessor) {
    if (typeof resultProcessor !== 'undefined')
      this.resultProcessor = resultProcessor;
    else
      throw { 'code': null, 'message': 'missing result processor argument' };

    if (typeof resultProcessor !== 'undefined')
      this.errorProcessor = errorProcessor;
    else
      this.errorProcessor = null;

    // perfrorms the query to the Reddit API using the current bearer token
    // taken from the grandmother RedditClient class instance
    // and calls the callback set on the mother RedditClient.call instance when the result is due
    // if the errorProcessor function was set on the RedditClient.call instance
    // then this will be called in case the HTTP status code from the API call is not 200
    this.after = function(httpMethod, apiPath, requestData) {
      if (typeof httpMethod !== 'undefined')
        this.httpMethod = httpMethod;
      else
        throw { 'code': null, 'message': 'missing method argument' };

      if (typeof apiPath !== 'undefined')
        this.apiPath = apiPath;
      else
        throw { 'code': null, 'message': 'missing path argument' };

      this.requestData = (typeof requestData !== 'undefined') ? requestData : null;

      time_now = Date.now();

      if (time_now > sessionExpiration)
        throw { 'code': null, 'message': 'login session expired' };

      if (time_now > tokenExpiration)
        refresh();
      
      var apiRequest = new XMLHttpRequest();
      apiRequest.onreadystatechange = function() {
        if (apiRequest.readyState == 4) {
          if (apiRequest.status == 200)
            resultProcessor(apiRequest);
          else
            if errorProcessor
              errorProcessor(apiRequest)
            else
              throw { 'code': apiRequest.status, 'message': 'request failed' }
        }
      }
      xhttp.open(httpMethod, 'https://oauth.reddit.com'+apiPath, true);
      xhttp.setRequestHeader('User-Agent', "{{ user_agent }}");
      xhttp.setRequestHeader('Authorization', 'bearer '+token);
      xhttp.send();
    }
  }

  // ping backend to let it know that there is an active client now
  // and obtain the current the bearer token
  refresh();
}
