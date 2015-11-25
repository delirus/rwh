function RedditClient() {
  var _client = this;

  // extracts the value of a cookie with given name
  var getCookie = function(cookieName) {
    var cookieIdentifier = cookieName + '=';
    var allCookies = document.cookie.split(';');
    for(var i=0; i < allCookies.length; i++) {
      var cookie = allCookies[i];
      while (cookie.charAt(0)==' ')
        cookie = cookie.substring(1);
      if (cookie.indexOf(cookieIdentifier) == 0)
        return cookie.substring(cookieIdentifier.length, cookie.length);
    }
  }

  // poll <app_url>/auth/active to let the backend know that the client is active
  // it also requests a new bearer token if the old one has already expired
  // this should be called periodically to keep the login session alive
  this.refresh = function() {
    var processActiveAuthResponse = function() {
      if (sessionStatusRequest.readyState == 4 ) {
        if (sessionStatusRequest.status == 200) {
          jsonResponse = JSON.parse(sessionStatusRequest.responseText)
          _client.sessionId = jsonResponse.session_id
          _client.sessionStatus = jsonResponse.session_status
          _client.token = jsonResponse.token
          _client.tokenExpiration = Date.now() + 1000*parseInt(jsonResponse.token_expires_in)
        }
        else if (sessionStatusRequest.status != 500)
          throw { 'code': sessionStatusRequest.status,
                  'message': JSON.parse(sessionStatusRequest.responseText).error }
        else
          throw { 'code': 500, 'message': 'internal server error' }
      }
    };
    var sessionStatusRequest = new XMLHttpRequest();
    sessionStatusRequest.onreadystatechange = processActiveAuthResponse();
    sessionStatusRequest.open("GET", "{{ app_url }}/auth/active", false);
    sessionStatusRequest.setRequestHeader("User-Agent", "{{ user_agent }}");
    sessionStatusRequest.send();

    // cookies were refreshed in the above request to the <app>/auth/active URL
    // so the "session_expires_in" cookie value is now valid
    _client.sessionExpiration = Date.now() + 1000*parseInt(getCookie('session_expires_in'));
  }
  
  // registers a new callback function that will be called after query
  // intended use is this:
  //     processQueryResult = new redditClientInstance.call(myResultProcessingFunction)
  //     processQueryResult.after('GET', '/api/v1/me')
  // the parameters are the callback function
  // and error processing function, which will be called if the API request fails
  // the error processing function can be omitted
  this.call = function(resultProcessor, errorProcessor) {
    _call = this;
    _call_client = _client;

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

      if (time_now > _call_client.sessionExpiration)
        throw { 'code': null, 'message': 'login session expired' };

      if (time_now > _call_client.tokenExpiration)
        _call_client.refresh();
      
      var apiRequest = new XMLHttpRequest();
      apiRequest.onreadystatechange = function() {
        if (apiRequest.readyState == 4) {
          if (apiRequest.status == 200)
            _call.resultProcessor(apiRequest);
          else
            if (_call.errorProcessor)
              _call.errorProcessor(apiRequest)
            else
              throw { 'code': apiRequest.status, 'message': 'request failed' }
        }
      }
      apiRequest.open(httpMethod, 'https://oauth.reddit.com'+apiPath, true);
      apiRequest.setRequestHeader('User-Agent', "{{ user_agent }}");
      apiRequest.setRequestHeader('Authorization', 'bearer '+_call_client.token);
      apiRequest.send();
    }
  }

  // let the backend know that there is an active client now
  // and obtain a valid bearer token from current login session
  this.refresh();
}
