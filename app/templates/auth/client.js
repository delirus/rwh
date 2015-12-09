function AuthClient() {
  var _client = this;

  // this variable value needs to be sent in HTTP headers
  // to authorize requests to <app_url>/auth/active and <app_url>/auth/logout
  // it set by server while sending the client source and
  // it never should be modified by any JS code
  var sessionId = "{{ session }}";

  var sessionStatus = 'uninitialized';
  this.isReady = function() {
    return (sessionStatus == 'active');
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

          sessionId = jsonResponse.session_id;
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
        else if (Math.floor(logoutRequest.status / 100) != 5)
          jsonErrorResponse = JSON.parse(sessionStatusRequest.responseText);
          jsonErrorResponse.code = sessionStatusRequest.status;
          throw jsonErrorResponse;
        else
          throw { 'code': sessionStatusRequest.status,
                  'message': 'server error' };
      }
    };
    sessionStatusRequest.open("GET", "{{ app_url }}/auth/active", true);
    sessionStatusRequest.setRequestHeader('X-Csrf-Token', sessionId);
    sessionStatusRequest.send();
  }

  // logs out the current login session
  this.logout = function() {
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
        else
          throw { 'code': logoutRequest.status,
                  'message': 'server error' };
      }
    };
    sessionStatusRequest.open("GET", "{{ app_url }}/auth/logout", true);
    sessionStatusRequest.setRequestHeader('X-Csrf-Token', sessionId);
    sessionStatusRequest.send();
  }
  
  // creates an object that registers a new callback function
  // that will be called after an API query called on this object finishes
  //
  // intended use is this:
  //     processQueryResult = new authClientInstance.RequestResultHandler(myResultProcessingFunction)
  //     processQueryResult.after('GET', '/api/v1/me')
  // (see this.call() function for shorter syntax and
  //  RequestResultHandler.after function for its parameters)
  //
  // the only parameter to the constructor is the callback function
  // which will be called when the results of the API requests
  // originated from this instance are ready
  this.RequestResultHandler = function(resultProcessor) {
    var handlerResultProcessor = null;
    if (typeof resultProcessor !== 'undefined')
      handlerResultProcessor = resultProcessor;
    else
      throw { 'code': null, 'message': 'missing result processor argument' };
    
    var clientIsReady = _client.isReady;
    var refreshClient = _client.refresh;

    var clientWaitingRequests   = waitingRequests;

    var clientToken             = getToken;
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
    // the compulsory parameters are the HTTP method string (e.g. "GET"),
    // the Reddit API path (e.g. "/api/v1/me") and the requestData argument
    // which may be omitted if there are no data to be sent in the request body
    // (most likely with "POST" or "PUT" HTTP method)
    // the requestData is assumed to be either string,
    // in which case it will be posted as-is,
    // or an object, in which case it must be JSON that will be stringified
    this.after = function(httpMethod, apiPath, requestData) {
      var requestResultProcessor = handlerResultProcessor;

      var givenHttpMethod = null;
      if (typeof httpMethod !== 'undefined')
        givenHttpMethod = httpMethod;
      else
        throw { 'code': null, 'message': 'missing method argument' };

      var givenApiPath = null;
      if (typeof apiPath !== 'undefined')
        givenApiPath = apiPath;
      else
        throw { 'code': null, 'message': 'missing path argument' };

      givenRequestData = (typeof requestData !== 'undefined') ? requestData : null;

      var time_now = Date.now();

      if (clientIsReady()) {
        if (time_now > clientSessionExpiration())
          throw { 'code': null, 'message': 'login session expired' };

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
                      'https://oauth.reddit.com'+givenApiPath,
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
          apiRequest.setRequestHeader('Authorization', 'bearer '+clientToken());
          apiRequest.send(apiRequestData);
        }
      }
      else {
        apiRequest.sendWithData = function() {
          apiRequest.setRequestHeader('Authorization', 'bearer '+clientToken());
          apiRequest.send();
        }
      }
      // only send the request if the client has already been initiated
      // queue it for after the initiation succeeds otherwise
      if (clientIsReady())
        apiRequest.sendWithData();
      else
        clientWaitingRequests.push(apiRequest);
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
