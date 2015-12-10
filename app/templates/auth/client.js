function AuthClient() {
  var _client = this;

  // this variable value needs to be sent in HTTP headers
  // to authorize requests to <app_url>/auth/active and <app_url>/auth/logout
  // it set by server while sending the client source and
  // it never should be modified by any JS code
  var sessionSecret = "{{ session_secret }}";
  var getSessionSecret = function() {
    return sessionSecret;
  }

  var sessionStatus = 'uninitialized';
  this.getSessionStatus = function() {
    return sessionStatus;
  }

  // extracts the value of a cookie with the given name
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

  // authorization token for making API calls
  var token = null;
  var getToken = function() {
    return token;
  }

  var tokenExpiration = null;
  var getTokenExpiration = function() {
    return tokenExpiration;
  }

  var sessionExpiration = null;
  var getSessionExpiration = function() {
    return sessionExpiration;
  }

  // API requests that were called before the client was fully initialized
  // they will be called after the initialization finishes
  var waitingRequests = [];

  // polls the <app_url>/auth/active to let the backend know the client lives
  // it also requests a new bearer token if it's missing or has already expired
  // this should be called periodically to keep the login session alive
  this.refresh = function() {
    sessionStatus = 'verifying';
    var sessionStatusRequest = new XMLHttpRequest();
    sessionStatusRequest.onreadystatechange = function() {
      if (sessionStatusRequest.readyState == 4 ) {
        if (sessionStatusRequest.status == 200) {
          jsonResponse = JSON.parse(sessionStatusRequest.responseText);

          token = jsonResponse.token;
          tokenExpiration = Date.now() + 1000*parseInt(jsonResponse.token_expires_in);

          sessionSecret = jsonResponse.session_secret;
          // cookies were refreshed in this very request
          // so the value of the "session_expires_in" cookie is now valid
          sessionExpiration = Date.now() + 1000*parseInt(getCookie('session_expires_in'));
          sessionStatus = jsonResponse.session_status;

          // process requests that were issued before the client was initialized
          numberOfWaitingRequests = waitingRequests.length;
          if (numberOfWaitingRequests > 0) {
            for (var i=0; i<numberOfWaitingRequests; i++) {
              request = waitingRequests[i];
              request.sendWithData();
            }
          }
        }
        else if (Math.floor(sessionStatusRequest.status / 100) != 5) {
          jsonErrorResponse = JSON.parse(sessionStatusRequest.responseText);
          jsonErrorResponse.code = sessionStatusRequest.status;
          throw jsonErrorResponse;
        }
        else {
          throw { 'code': sessionStatusRequest.status,
                  'error': 'server error' };
        }
      }
    };
    sessionStatusRequest.open("GET", "{{ app_url }}/auth/active", true);
    sessionStatusRequest.setRequestHeader('X-Session-Secret', sessionSecret);
    sessionStatusRequest.send();
  }

  // logs out the current login session
  this.logout = function() {
    sessionStatus = 'unlogged';

    clearInterval(_client.heartbeat);

    var logoutRequest = new XMLHttpRequest();
    logoutRequest.onreadystatechange = function() {
      if (logoutRequest.readyState == 4 ) {
        if (Math.floor(logoutRequest.status / 100) == 2) {
          jsonResponse = JSON.parse(logoutRequest.responseText);
          return jsonResponse.session_status;
        }
        else if (Math.floor(logoutRequest.status / 100) != 5) {
          jsonErrorResponse = JSON.parse(logoutRequest.responseText);
          jsonErrorResponse.code = logoutRequest.status;
          throw jsonErrorResponse;
        }
        else {
          throw { 'code': logoutRequest.status,
                  'error': 'server error' };
        }
      }
    };
    logoutRequest.open("GET", "{{ app_url }}/auth/logout", true);
    logoutRequest.setRequestHeader('X-Session-Secret', sessionSecret);
    logoutRequest.send();
  }
  
  // creates an object that registers a new callback function
  // that will be called after an API query called on this object finishes
  //
  // intended use can look for example like this:
  //     processQueryResult = new authClientInstance.RequestResultHandler(myResultProcessingFunction)
  //     processQueryResult.afterRedditRequest('GET', '/api/v1/me')
  // (see AuthClient.call() function for shorter syntax)
  //
  // the only parameter to the constructor is the callback function
  // which will be called when the results of the API requests
  // originated from this instance are ready
  this.RequestResultHandler = function(resultProcessor) {
    var _handler = this;

    var handlerResultProcessor = null;
    if (typeof resultProcessor !== 'undefined')
      handlerResultProcessor = resultProcessor;
    else
      throw { 'code': null, 'error': 'missing result processor argument' };
    
    var sessionStatus = _client.getSessionStatus;
    var refreshClient = _client.refresh;

    var clientWaitingRequests   = waitingRequests;

    var clientSessionSecret     = getSessionSecret;

    var clientToken             = function() {
      return 'bearer '+getToken();
    }
    var clientTokenExpiration   = getTokenExpiration;
    var clientSessionExpiration = getSessionExpiration;

    // perfrorms the API request to the Reddit API
    // using the current bearer token from the grandparent AuthClient instance
    // and calls the callback set in the mother AuthClient.RequestResultHandler
    // when the result of the API request is available
    //
    // it is up to the resultProcessor function (see RequestResultHandler init)
    // to check the returned status and either prcess data or handle an error
    // 
    // the parameters are following:
    // HTTP method string (e.g. "GET"),
    // API base URL (e.g. 'https://oauth.reddit.com'),
    // the API path (e.g. "/api/v1/me"),
    // the requestData,
    // authorization HTTP header name (e.g. 'Authorization') and
    // call to get the authorization header value (e.g. clientToken function)
    //
    // the requestData argument may be omitted or given as null
    // if no data are supposed to be sent in the request body,
    // otherwise it is assumed to be either string, which is posted as-is,
    // or a JSON object, which will be jsonified to a string
    //
    // authorization HTTP header name and the authorization header value call
    // can be omitted, in which case they are not sent with the request
    // if the authorization header name is given, it is expected to be a string
    // and the authorization header value is expected to be name of a function
    // which returns the value of the header to authorize the API request
    this.callProcessorAfterRequest = function(httpMethod, apiUrl, apiPath, requestData, authHeader, getAuthTokenCall) {
      var requestResultProcessor = handlerResultProcessor;

      var givenHttpMethod = null;
      if (typeof httpMethod !== 'undefined')
        givenHttpMethod = httpMethod;
      else
        throw { 'code': null, 'error': 'missing HTTP method argument' };

      var givenApiUrl = null;
      if (typeof apiUrl !== 'undefined')
        givenApiUrl = apiUrl;
      else
        throw { 'code': null, 'error': 'missing API base URL argument' };

      var givenApiPath = null;
      if (typeof apiPath !== 'undefined')
        givenApiPath = apiPath;
      else
        throw { 'code': null, 'error': 'missing API path argument' };

      givenRequestData = (typeof requestData !== 'undefined') ? requestData : null;

      var givenAuthHeader = null;
      if (typeof authHeader !== 'undefined')
        givenAuthHeader = authHeader;
      else
        throw { 'code': null, 'error': 'missing auhotization header argument' };

      var givenAuthTokenCall = null;
      if (typeof getAuthTokenCall !== 'undefined')
        givenAuthTokenCall = getAuthTokenCall;
      else
        throw { 'code': null, 'error': 'missing authorization token argument' };

      var time_now = Date.now();

      if (sessionStatus() === 'active') {
        if (time_now > clientSessionExpiration())
          throw { 'code': null, 'error': 'login session expired' };

        if (time_now > clientTokenExpiration())
          refreshClient();
      }
      
      var apiRequest = new XMLHttpRequest();
      apiRequest.onreadystatechange = function() {
        if (apiRequest.readyState == 4) {
          requestResultProcessor(apiRequest);
        }
      }
      apiRequest.open(givenHttpMethod,
                      givenApiUrl+givenApiPath,
                      true);
      // this header is no longer forbidden per-spec
      // so it should work in the newest browser versions...
      apiRequest.setRequestHeader('User-Agent', "{{ user_agent }}");
      if (givenRequestData) {
        stringData = null
        if (typeof givenRequestData === 'object') {
          apiRequest.setRequestHeader('Content-Type',
                                      'application/json; charset=utf-8');
          stringData = JSON.stringify(requestData);
        }
        else {
          stringData = requestData.toString();
        }
        apiRequest.apiRequestData = stringData;
        apiRequest.setRequestHeader('Content-Length', stringData.length);
        apiRequest.sendWithData = function() {
          if (givenAuthHeader)
            apiRequest.setRequestHeader(givenAuthHeader, givenAuthTokenCall());
          apiRequest.send(apiRequestData);
        }
      }
      else {
        apiRequest.sendWithData = function() {
          if (givenAuthHeader)
            apiRequest.setRequestHeader(givenAuthHeader, givenAuthTokenCall());
          apiRequest.send();
        }
      }
      // only send the request if the client has already been initiated
      // queue it for after the initiation succeeds otherwise
      if (sessionStatus() === 'active')
        apiRequest.sendWithData();
      else if (sessionStatus() === 'verifying')
        clientWaitingRequests.push(apiRequest);
      else
        throw {'code': null, 'error': 'inactive login session'}
    }

    this.afterRedditRequest = function(httpMethod, redditApiPath, requestData) {
      if (typeof requestData !== 'undefined')
        _handler.callProcessorAfterRequest(httpMethod, 'https://oauth.reddit.com', redditApiPath, requestData, 'Authorization', clientToken);
      else
        _handler.callProcessorAfterRequest(httpMethod, 'https://oauth.reddit.com', redditApiPath, null, 'Authorization', clientToken);
    }

    this.afterRwhRequest = function(httpMethod, rwhApiPath, requestData) {
      if (typeof requestData !== 'undefined')
        _handler.callProcessorAfterRequest(httpMethod, '{{ app_url }}', rwhApiPath, requestData, 'X-Session-Secret', clientSessionSecret);
      else
        _handler.callProcessorAfterRequest(httpMethod, '{{ app_url }}', rwhApiPath, null, 'X-Session-Secret', clientSessionSecret);
    }
  }

  // shorthand for calling requestResultHandler that enables this syntax:
  //     authClient.call(myProcessinFunction).after(...);
  this.call = function(resultProcessor) {
    return new this.RequestResultHandler(resultProcessor);
  }

  // let the backend know that there is an active client now
  // and obtain a valid bearer token from current login session
  // and the session validity duration cookie
  this.refresh();
  
  // refresh session at least three times before it expires
  this.heartbeat = setInterval(this.refresh, 333*parseInt(getCookie('session_expires_in')));
}

authClient = new AuthClient();
