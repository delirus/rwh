function AuthClient() {
  var _client = this;

  this.ready = false;
  this.waiting_requests = [];

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
    _client.ready = false;
    var sessionStatusRequest = new XMLHttpRequest();
    sessionStatusRequest.onreadystatechange = function() {
      if (sessionStatusRequest.readyState == 4 ) {
        if (sessionStatusRequest.status == 200) {
          jsonResponse = JSON.parse(sessionStatusRequest.responseText);
          _client.sessionId = jsonResponse.session_id;
          _client.sessionStatus = jsonResponse.session_status;
          _client.token = jsonResponse.token;
          _client.tokenExpiration = Date.now() + 1000*parseInt(jsonResponse.token_expires_in);
          // cookies were refreshed in this very request
          // so the value of the "session_expires_in" cookie is now valid
          _client.sessionExpiration = Date.now() + 1000*parseInt(getCookie('session_expires_in'));

          _client.ready = true;
          // process requests that were issued before the client was initiated
          number_of_waiting_requests = _client.waiting_requests.length;
          if (number_of_waiting_requests > 0) {
            for (var i=0; i<number_of_waiting_requests; i++) {
              request = waiting_requests[i];
              request.sendWithData();
            }
          }
        }
        else if (sessionStatusRequest.status != 500)
          throw { 'code': sessionStatusRequest.status,
                  'message': JSON.parse(sessionStatusRequest.responseText).error }
        else
          throw { 'code': 500, 'message': 'internal server error' }
      }
    };
    sessionStatusRequest.open("GET", "{{ app_url }}/auth/active", true);
    sessionStatusRequest.send();
  }
  
  // registers a new callback function that will be called
  // after a query called on this object finishes
  // intended use is this:
  //     processQueryResult = new authClientInstance.requestResultHandler(myResultProcessingFunction)
  //     processQueryResult.after('GET', '/api/v1/me')
  // (see "call" function for shorthand syntax)
  // the parameters are the callback function
  // and error processing function to called if the API request fails
  // if the error processing function is omitted, an error is thrown instead
  this.requestResultHandler = function(resultProcessor) {
    var _handler = this;
    var _handler_client = _client;

    if (typeof resultProcessor !== 'undefined')
      this.resultProcessor = resultProcessor;
    else
      throw { 'code': null, 'message': 'missing result processor argument' };

    // perfrorms the query to the Reddit API using the current bearer token
    // taken from the grandmother AuthClient class instance
    // and calls the callback set in the mother AuthClient.requestResultHandler
    // when the result is due
    // it is up to the resultProcessor function to check the status
    // and handle error
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

      if (_handler_client.ready) {
        if (time_now > _handler_client.sessionExpiration)
          throw { 'code': null, 'message': 'login session expired' };

        if (time_now > _handler_client.tokenExpiration)
          _handler_client.refresh();
      }
      
      var apiRequest = new XMLHttpRequest();
      apiRequest.onreadystatechange = function() {
        if (apiRequest.readyState == 4) {
          _handler.resultProcessor(apiRequest);
        }
      }
      apiRequest.open(httpMethod, 'https://oauth.reddit.com'+apiPath, true);
      // this header is no longer forbidden per-spec
      // so it should work in the newest browser versions...
      apiRequest.setRequestHeader('User-Agent', "{{ user_agent }}");
      apiRequest.setRequestHeader('Authorization', 'bearer '+_handler_client.token);
      if (requestData) {
        stringData = null
        if (typeof requestData === 'object') {
          apiRequest.setRequestHeader('Content-Type', 'application/json; charset=utf-8');
          stringData = JSON.stringify(requestData);
        }
        else {
          stringData = requestData.toString();
        }
        apiRequest.apiRequestData = stringData;
        apiRequest.setRequestHeader('Content-Length', stringData.length);
        apiRequest.sendWithData = function() {
          send(apiRequestData);
        }
      }
      else {
        apiRequest.sendWithData = apiRequest.send
      }
      // only send the request if the client has already been initiated
      // queue it for after the initiation succeeds otherwise
      if (_handler_client.ready)
        apiRequest.sendWithData();
      else
        _handler_client.waiting_requests.push(apiRequest);
    }
  }

  // shorthand for calling requestResultHandler that enables this syntax:
  //     authClient.call(myProcessinFunction).after(...);
  this.call = function(resultProcessor) {
    return new _client.requestResultHandler(resultProcessor);
  }

  // let the backend know that there is an active client now
  // and obtain a valid bearer token from current login session
  this.refresh();
}

authClient = new AuthClient();
