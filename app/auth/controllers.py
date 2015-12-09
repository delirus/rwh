from uuid import uuid4
from json import loads as parse_json_string
from datetime import timedelta
from datetime import datetime
from pytz import utc
from urllib.parse import urlencode
from urllib.request import Request as client_http_request
from urllib.request import HTTPBasicAuthHandler
from urllib.request import build_opener, urlopen
from hashlib import sha256
from flask import Blueprint, request, session, make_response, render_template, flash, redirect, url_for, jsonify

from app import db, rwh

from app.auth.models import LoginSession


# unfortunately, datetime.datetime.utcnow() is timezone naive...
def utcnow():
    return datetime.now(tz=utc)


"""
The blueprint for hadling URL's under the /auth/* path.
These paths are to be used for signing in and maintaing active users.
"""
auth_blueprint = Blueprint('auth', __name__, url_prefix='/auth')


def get_login_session():
    """
    Retrieves the "session_id" and "LoginSession" object that correspond
    to the value from the client session cookie.
    """
    login_session = None
    session_id    = session.get('session_id')
    if session_id:
        login_session = LoginSession.query.filter_by(id=session_id).first()
    return login_session, session_id


def authenticated(call):
    """
    This function is to be used as decorator for Flask routes
    that are only allowed to be accessed by authenticated users.

    e.g. route /private_path defined as

        @route("/private_path")
        @authenticated
        def private_path(...):
          ...

    (mind the order of decorators) can be accessed only by authenticated user.
    Non-authenticated users will be redirected to the /auth/login URL
    and the redirect_url cookie will be set for them to come back after login.

    This decorator should only be used for routes that are accessed directly
    by the user (e.g. by entering them to the browser address bar)
    and the user can respond to the authentication request
    after being redirected to the external login page.
    It should not be used for paths that are part of the API
    (see @authorized decorator for those).
    """
    def authenticated_call():
        login_session, session_id = get_login_session()
        if login_session and (login_session.status == LoginSession.status_active):
            return call()
        else:
            login_redirect_response = redirect(url_for('auth.reddit_login'))
            login_redirect_response.set_cookie('redirect_url', request.url)
            return login_redirect_response
    return authenticated_call


def request_is_authorized(login_session, request):
    """
    Checks that the request contains the 'X-Session-Secret' header
    and that the value matches with the current session ID.
    This value is rendered as private javascript variable in the client.js
    and should be sent by the client with every request.

    Moreover, it checks that the 'Referer' header starts with the app URL.
    This way only the calls made from one of the app pages can pass.

    The arguments are the active login_session object and the (Flask) request.

    It returns True if the referrer is allowed and CSRF token checks out,
    False otherwise.

    This function exists as separate call because it is used in multiple
    places and the /auth/active and /auth/logout endpoints
    has finer error reporting and perform additional cookie operations
    than the clean @authorized decorator used for other calls.
    """
    referer_header = request.headers.get('Referer')
    correct_referer = False
    if request.headers.get('Referer'):
        if request.headers.get('Referer').startswith(rwh.config['APP_URL']):
            correct_referer = True

    expected_token = login_session.secret
    provided_token = request.headers.get('X-Session-Secret')

    return ((expected_token == provided_token) and correct_referer)


def authorized(call):
    """
    This is a decorator that should be used for paths that are API endpoints.

    For example:
        @profile_blueprint.path('/sshkey', ...)
        @authorized
        def sshkey():
            ...

    It will check for the presence of the 'X-Session-Secret' header
    in the HTTP request and compare it to the current login session ID.
    It also verifies that the 'Referer' header starts with the app URL
    (the function request_is_authorized() is used internally).

    If a valid login session cannot be determined status code 401
    and JSON with error description 'not logged in' is returned.
    If the header is missing or does not have the correct value,
    the response status code will be 403 and the JSON with error description
    'unauthorized request'.

    If everything checks out, the decorated call will be executed.
    """
    def authorized_call():
        login_session, session_id = get_login_session()

        if (not login_session):
            not_logged_in_response = jsonify({'error': 'not logged in'})
            not_logged_in_response.status_code = 401

            return not_logged_in_response

        if (request_is_authorized(login_session, request)):
            # this check is made here so that we can report proper error cause
            # to a properly authenticated client with outdated session secret
            # but not leak the session status via a malicious CSRF request
            # i.e. only client from our app site that sent a proper CSRF token
            # (but for session that is not valid any more) can get this error
            # everyone else will get just the 403 "unauthorized request" bellow
            if (login_session.status == LoginSession.status_active):
                return call()
            else:
                invalid_session_response = jsonify({'error': 'invalid session'})
                invalid_session_response.status_code = 401

                return not_logged_in_response
        else:
            not_authorized_response = jsonify({'error': 'unauthorized request'})
            not_authorized_response.status_code = 403

            return not_authorized_response

    return authorized_call


@auth_blueprint.route('/client.js')
def client_js():
    """
    Renders the client JS code that deals with Reddit API.
    This code is not static since it contains session secrets
    and values that depend on the app configuration.

    This endponint will only respond when the user is logged in
    (has active session cookie) and the request comes from a URL
    that starts with the app URL (value of the 'Referer' header is checked).

    The difference from the @authorized decorator is that these security checks
    do not look at the value of the 'X-Session-Secret' which is only known after
    the client downloads this JS code (included as a private variable within).
    """
    login_session, session_id = get_login_session()
    if (not login_session):
        not_logged_in_response = jsonify({'error': 'not logged in'})
        not_logged_in_response.status_code = 401

        return not_logged_in_response

    correct_referer = False
    if request.headers.get('Referer'):
        if request.headers.get('Referer').startswith(rwh.config['APP_URL']):
            correct_referer = True
    if ((not correct_referer) or (login_session.status != LoginSession.status_active)):
        not_authorized_response = jsonify({'error': 'unauthorized request'})
        not_authorized_response.status_code = 403

        return not_authorized_response

    return render_template('auth/client.js',
                           session_secret = login_session.secret,
                           user_agent     = rwh.config['APP_USER_AGENT_CLIENT'],
                           app_url        = rwh.config['APP_URL'])


def token_request(uri, post_data):
    """
    This function encapsulates the code used to make the request
    to the (reddit) OAuth2 endpoint that is shared between
    obtaining the first, refreshing and revoking the token.

    The parameters are the endpoint URI and dictionary with the post data
    to be JSONified and sent with the POST request to the URI.
    """
    request_data = urlencode(post_data).encode('utf-8')

    token_request = client_http_request(uri, method='POST', data=request_data)
    token_request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    token_request.add_header('User-Agent', rwh.config['APP_USER_AGENT_SERVER'])

    authenticator = HTTPBasicAuthHandler()
    authenticator.add_password(realm='reddit', uri=uri,
                               user=rwh.config['APP_ID'], passwd='')
    authenticated_opener = build_opener(authenticator)

    request_result = authenticated_opener.open(token_request)

    status_code = request_result.getcode()
    result_body = None
    if request_result:
        result_body = request_result.read().decode('utf-8')
    if result_body and (len(result_body.strip()) > 0):
        result_data = parse_json_string(result_body)
    else:
        result_data = None

    return result_data, status_code
    

def obtain_token(login_session, authorization_code):
    """
    Calls OAuth2 server to get the API bearer token and refresh token
    using the one-time code previously sent to the /auth/login endpoint
    after the first stage of authorization (user approval and redirect).

    This function is used by the reddit_login() call.
    """
    authorization_uri  = 'https://www.reddit.com/api/v1/access_token'
    authorization_post_data = {
      'grant_type':  'authorization_code',
      'code':         authorization_code,
      'redirect_uri': "%s%s" % (rwh.config['APP_URL'], url_for('auth.reddit_login'))
    }

    authorization_data, status_code = token_request(authorization_uri,
                                                    authorization_post_data)

    token, expires_in, refresh_token = None, None, None
    # do not update anythong if there was an error
    if (status_code == 200):
        token         = authorization_data.get('access_token')
        expires_in    = authorization_data.get('expires_in')
        refresh_token = authorization_data.get('refresh_token')

    # only update the LoginSession object if all information was returned
    if (token and expires_in and refresh_token):
        login_session.token         = token
        login_session.token_expires = utcnow() + timedelta(seconds=expires_in)
        login_session.refresh_token = refresh_token

    return status_code


def get_reddit_username(login_session):
    username_request = client_http_request('https://oauth.reddit.com/api/v1/me',
                                           method='GET')
    username_request.add_header('User-Agent', rwh.config['APP_USER_AGENT_SERVER'])
    username_request.add_header('Authorization', "bearer %s" % login_session.token)
    response = urlopen(username_request)

    http_status = response.getcode()
    response_body = response.read().decode('utf-8')
    if ((http_status == 200) and (len(response_body.strip()) > 0)):
        response_data = parse_json_string(response_body)

        username = response_data['name'] 

        hash_function = sha256()
        hash_function.update(username.encode('utf-8'))

        return hash_function.hexdigest()
    else:
        return None


@auth_blueprint.route('/login', strict_slashes=False)
def reddit_login():
    """
    This path serves as the app redirect_uri and should be accessed
    by the client browser directly.

    The first time it is accessed it attempts to initiate new login session.
    What exactly happens then depends on the stage the authorization is in.
    It maintains the state via storing LoginSession object (state),
    setting the encripted 'session_id' cookie to identify corresponding object
    and maintaining 'session_expires_in' cookie (see /auth/active endpoint).

    In case of faliure the template login_error.html is rendered
    and the corresponding error is flashed. More underlying information
    can ge obtained from the status_code that is returned in this case.
    """
    # get the LoginSession object and the session_id from request cookies
    login_session, session_id = get_login_session()
    if login_session:
        if (login_session.status == LoginSession.status_initiating):
            # We got redirected here to finish authorization for a session
            # that user was asked to authorize on an OAuth2 server.
            code  = request.args.get('code')
            state = request.args.get('state')

            if not (code and state):
                # We did not get the code or cannot check that
                # we are authorizing one of sessions that we initiated
                # (missing state).
                # Cancel the authorization by setting the session to
                # the failed state, unset the cookies and display the error.
                error = request.args.get('error')
                if not error:
                    error = "could not authorize session"

                login_session.status = LoginSession.status_failed
                db.session.add(login_session)
                db.session.commit()

                flash(error)
                authorization_failed_response = make_response(render_template('auth/login_error.html'))

                if ('session_id') in session:
                    session.pop('session_id')
                authorization_failed_response.set_cookie('session_expires_in', '-1', expires=0)
                authorization_failed_response.status_code = 401

                return authorization_failed_response

            if (state == session_id):
                # User approved request on the OAuth2 server and got redirected
                # here to finish the authorization.
                # We attempt to get the bearer token using the given code now.
                status_code = obtain_token(login_session, code)

                if (status_code == 200):
                    username = get_reddit_username(login_session)
                    if username:
                        login_session.username = username
                    else:
                        login_session.status = LoginSession.status_failed
                        db.session.add(login_session)
                        db.session.commit()
                        
                        flash('could not get username using retrieved bearer token')
                        initiation_failed_response = make_response(render_template('auth/login_error.html'))
                        if ('session_id') in session:
                            session.pop('session_id')
                        initiation_failed_response.set_cookie('session_expires_in', '-1', expires=0)

                        initiation_failed_response.status_code = status_code

                        return initiation_failed_response

                    # Bearer token successfully retrieved.
                    # Redirect user to the URL specified by the redirect_url
                    # cookie or the default URL (app root)
                    login_session.status = LoginSession.status_active
                    db.session.add(login_session)
                    db.session.commit()

                    default_redirect_url = request.url_root
                    given_redirect_url   = request.cookies.get('redirect_url')
                    if given_redirect_url and (len(given_redirect_url) > 0):
                        login_redirect_response = redirect(given_redirect_url)
                        # unset the redirect_url after it is used
                        login_redirect_response.set_cookie('redirect_url', '', expires=0)
                    else:
                        login_redirect_response = redirect(default_redirect_url)

                    session['session_id'] = session_id
                    session_expires_in    = rwh.config['SESSION_DURATION']
                    login_redirect_response.set_cookie('session_expires_in', session_expires_in)

                    return login_redirect_response
                else:
                    # Getting the bearer token from the OAuth2 server failed.
                    # (server returned status different than 200).
                    # Record the sate of the session as failed,
                    # unset the cookies and display error.
                    login_session.status = LoginSession.status_failed
                    db.session.add(login_session)
                    db.session.commit()

                    flash('could not obtain bearer token from OAuth2 server')
                    initiation_failed_response = make_response(render_template('auth/login_error.html'))
                    if ('session_id') in session:
                        session.pop('session_id')
                    initiation_failed_response.set_cookie('session_expires_in', '-1', expires=0)

                    initiation_failed_response.status_code = status_code

                    return initiation_failed_response
            else:
                # User got redirected here from OAuth2 server
                # (or tries to pretend that he did)
                # and attempts to finish an authorization for different session
                # than the one that is in his session_id.
                # Unset the cookies and display error.
                flash('no such session started')
                session_not_found_response = make_response(render_template('auth/login_error.html'))

                if ('session_id') in session:
                    session.pop('session_id')
                session_not_found_response.set_cookie('session_expires_in', '-1', expires=0)
                session_not_found_response.status_code = 403
                
                return session_not_found_response
        elif (login_session.status == LoginSession.status_active):
            # Logged in user went to the login URL.
            # Show him an error with status code 409 (conflict).
            flash("already logged in")
            already_logged_response = make_response(render_template('auth/login_error.html'))
            already_logged_response.status_code = 409

            return already_logged_response
        else:
            # Session with the given session_id existes in the DB,
            # but is not an active or initiating session any more.
            # Unset the session_id and session_expires_in cookies and try again
            invalid_session_response = redirect(url_for('auth.reddit_login'))

            if ('session_id') in session:
                session.pop('session_id')
            invalid_session_response.set_cookie('session_expires_in', '-1', expires=0)

            return invalid_session_response
    else:
        # No session_id cookie was found.
        # Create new login session.
        session_id = str(uuid4())
        login_session = LoginSession(session_id) # default status='initiating'
        db.session.add(login_session)
        db.session.commit()

        app_id = rwh.config['APP_ID']
        app_url = "%s%s" % (rwh.config['APP_URL'], url_for('auth.reddit_login'))
        authorization_redirect_response = redirect("https://www.reddit.com/api/v1/authorize?client_id=%s&response_type=code&state=%s&redirect_uri=%s&duration=permanent&scope=identity,submit,edit" % (app_id, session_id, app_url))

        session['session_id'] = session_id
        session_expires_in = rwh.config['SESSION_DURATION']
        authorization_redirect_response.set_cookie('session_expires_in', session_expires_in)

        return authorization_redirect_response


def refresh_token(login_session):
    """
    Performs a call to the OAuth2 server and attempts to get new bearer token.
    This method should be called after the old token for the given LoginSession
    has expired and the access to needs to be maintained.

    This call is used by the /auth/active endpoint.
    """
    refresh_uri = 'https://www.reddit.com/api/v1/access_token'
    refresh_post_data = {
      'grant_type': 'refresh_token',
      'refresh_token': login_session.refresh_token
    }

    refresh_result, status_code = token_request(refresh_uri, refresh_post_data)

    new_token, token_expires_in = None, None
    if (status_code == 200):
        new_token = refresh_result.get('access_token')
        token_expires_in = refresh_result.get('expires_in')

    if (new_token and token_expires_in):
        login_session.token = new_token
        login_session.token_expires = utcnow() + timedelta(seconds=token_expires_in)

    return status_code


@auth_blueprint.route('/active', strict_slashes=False)
def active():
    """
    This is API only endpoint that should be called regulary (e.g. with AJAX)
    by any @authenticated page that wishes to maintain the login session.
    It returns JSON object with the session secret, status, (reddit) API token
    and expiration times in seconds for the session and the token.

    A client that wishes to make request to the Reddit API after the time
    of the token expiration should call this endpoint first.
    When this endpoint is accessed after the token expired,
    the server will attempt to re-activate the token (using refresh token)
    and returns the new token and its expiration time and the session info.

    Beside of that, a cookie 'session_expires_in' is set, which indicates
    how long will the app respond to this call. After the time
        now + session_expires_in
    the app will revoke its access and mark the session as expired.
    A client that wishes to get new token and continue making API requests
    will have to log in again and re-authorize the app.

    If the request is not successfull, the relevant cookies will be unset
    so that the client does not make the same errornous request again.
    """
    login_session, session_id = get_login_session()

    if (not session_id):
        unauthenticated_response = jsonify({'error': 'not logged in'})
        unauthenticated_response.set_cookie('session_expires_in', '-1', expires=0)
        unauthenticated_response.status_code = 401

        return unauthenticated_response

    if (login_session and (login_session.status != LoginSession.status_active)):
        invalid_session_response = jsonify({'error': 'invalid_session'})

        if ('session_id') in session:
            session.pop('session_id')
        invalid_session_response.set_cookie('session_expires_in', '-1', expires=0)

        invalid_session_response.status_code = 401

        return invalid_session_response

    if (not request_is_authorized(login_session, request)):
        invalid_token_response = jsonify({'error': 'unauthorized request'})
        invalid_token_response.status_code = 403

        return invalid_token_response
    
    time_now = utcnow()
    login_session.last_active = time_now

    status_code = 200
    if (time_now > login_session.token_expires):
        status_code = refresh_token(login_session)

    db.session.add(login_session)
    db.session.commit()

    session['session_id'] = session_id
    session_expires_in    = rwh.config['SESSION_DURATION']

    if (status_code == 200):
        token_expires_in = int(login_session.token_expires.strftime('%s')) - int(utcnow().strftime('%s')) 
        session_refreshed_response = jsonify({'session_secret': login_session.secret,
                                              'session_status': LoginSession.status_active,
                                              'token': login_session.token,
                                              'token_expires_in': token_expires_in})
        session_refreshed_response.set_cookie('session_expires_in', session_expires_in)
        session_refreshed_response.status_code = 200

        return session_refreshed_response
    else:
        # report error but give the client a chance to try again later
        refresh_failed_response = jsonify({'error': 'could not refresh token'})
        session['session_id'] = session_id
        refresh_failed_response.set_cookie('session_expires_in', session_expires_in)
        # the status code will be whatever error the refresh_token failed with
        refresh_failed_response.status_code = status_code
        
        return refresh_failed_response


def revoke_reddit_token(login_session):
    """
    Calls the OAuth2 server to manually revoke access for current bearer token.
    It should return status code 204 if everything goes well.
    The only argument is the LoginSession object that contains the token.
    
    This call is used by the /auth/logout endpoint
    and util.expire_old_sessions() periodic task.
    """
    token = login_session.token
    
    revoke_uri  = 'https://www.reddit.com/api/v1/revoke_token'
    revoke_post_data = {
      'token': token
    }

    revoke_result, status_code = token_request(revoke_uri, revoke_post_data)

    return status_code


@auth_blueprint.route('/logout', strict_slashes=False)
def logout():
    """
    This is API endpoint only that should be accessed indirectly
    e.g. using AJAX Javascript call from separate logout page.

    It always returns JSON object with result of the operation
    and sets the 'session_expires_in' cookie to present time
    (or unsets it if the session was invalid in the first place).
    """
    login_session, session_id = get_login_session()
    if login_session:
        if (not request_is_authorized(login_session, request)):
            invalid_token_response = jsonify({'error': 'unauthorized request'})
            invalid_token_response.status_code = 403

            return invalid_token_response

        if (login_session.status == LoginSession.status_active):
            revoke_status = revoke_reddit_token(login_session)

            if (revoke_status != 204):
                revoke_failed_response = jsonify({'error': 'could not revoke token'})
                # indicate error and refresh session and session_expires_in cookies
                # so that client can attempt to properly logout later
                revoke_failed_response.status_code = revoke_status
                session['session_id'] = session_id
                session_expires_in = rwh.config['SESSION_DURATION']
                revoke_failed_response.set_cookie('session_expires_in', session_expires_in)

                return revoke_failed_response

            login_session.status = LoginSession.status_unlogged
            db.session.add(login_session)
            db.session.commit()

            session_unlogged_response = jsonify({'session_id': session_id,
                                                 'session_status': LoginSession.status_unlogged})
            session_unlogged_response.status_code = 200
            if ('session_id') in session:
                session.pop('session_id')
            session_unlogged_response.set_cookie('session_expires_in', '-1', expires=0)

            return session_unlogged_response
        else:
            # this response is reason why this call cannot be simply @authorized
            session_invalid_response = jsonify({'session_id': session_id,
                                                'session_status': login_session.status})
            session_invalid_response.status_code = 202
            if ('session_id') in session:
                session.pop('session_id')
            session_invalid_response.set_cookie('session_expires_in', '-1', expires=0)

            return session_invalid_response
    else:
        session_not_found_response = jsonify({'session': session_id,
                                              'error': 'not logged in'})
        session_not_found_response.status_code = 401
        if ('session_id') in session:
            session.pop('session_id')
        session_not_found_response.set_cookie('session_expires_in', '-1', expires=0)

        return session_not_found_response
