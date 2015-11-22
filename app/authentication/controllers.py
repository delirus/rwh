import uuid
import json
from datetime import timedelta
from datetime import datetime 
utc = datetime.utcfromtimestamp
utcnow = datetime.utcnow
from urllib.parse import urlencode
from urllib.request import Request as client_http_request
from urllib.request import HTTPBasicAuthHandler as http_basic_auth_handler
from urllib.request import build_opener
from flask import Blueprint, request, render_template, redirect, session, url_for, jsonify

from app import db, rwh

from app.authentication.models import LoginSession


"""
The blueprint for hadling URL's under the /authenticatin/* path.
These paths are to be used for signing in and maintaing active users.
"""
login = Blueprint('authentication', __name__, url_prefix='/authentication')


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
    This function is to be used as decorator for Flask calls
    that are only allowed for authenticated users.
    e.g. if the route is defined as
    @authenticated
    @route("/stories")
    def stories(...)
    then the route /stories can be accessed only by authenticated users.
    Non-authenticated user will be redirected to the /authentication/login URL.
    """
    def authenticated_call():
        login_session, session_id = get_login_session()
        if login_session and (login_session.status == LoginSession.status_open):
            call()
        else:
            return redirect(url_for('authentication.reddit_login'))
    return authenticated_call


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
    token_request.add_header('User-Agent', rwh.config['APP_USER_AGENT'])

    authenticator = http_basic_auth_handler()
    authenticator.add_password(realm='reddit', uri=uri,
                               user=rwh.config['APP_ID'], passwd='')
    authenticated_opener = build_opener(authenticator)

    request_result = authenticated_opener.open(token_request)

    status_code = request_result.getcode()
    result_body = None
    if request_result:
        result_body = request_result.read().decode('utf-8')
    if result_body and (len(result_body.strip()) > 0):
        result_data = json.loads(result_body)
    else:
        result_data = None

    return result_data, status_code
    

def obtain_token(login_session, authorization_code):
    authorization_uri  = 'https://www.reddit.com/api/v1/access_token'
    authorization_post_data = {
      'grant_type':  'authorization_code',
      'code':         authorization_code,
      'redirect_uri': rwh.config['APP_URL']
    }

    authorization_data, status_code = token_request(authorization_uri,
                                                    authorization_post_data)

    token, expires_in, refresh_token = None, None, None
    if (status_code == 200):
        token         = authorization_data.get('access_token')
        expires_in    = authorization_data.get('expires_in')
        refresh_token = authorization_data.get('refresh_token')

    if (token and expires_in and refresh_token):
        login_session.token         = token
        login_session.token_expires = utcnow() + timedelta(seconds=expires_in)
        login_session.refresh_token = refresh_token

    return status_code


@login.route('/login', strict_slashes=False)
def reddit_login():
    login_session, session_id = get_login_session()
    if login_session:
        if (login_session.status == LoginSession.status_initiating):
            code  = request.args.get('code')
            state = request.args.get('state')

            if not (code and state):
                error = request.args.get('error')
                if not error:
                    error = "could not get authorization code for this session"

                login_session.status = LoginSession.status_failed
                db.session.add(login_session)
                db.session.commit()

                session.pop('session_id')
                session.pop('session_expires')
                return jsonify({'error': error}), 401

            if (state == session_id):
                status_code = obtain_token(login_session, code)
                if (status_code == 200):
                    login_session.status = LoginSession.status_active
                    db.session.add(login_session)
                    db.session.commit()

                    login_redirect_response = redirect(url_for('authentication.active'))
                    session['session_id'] = session_id

                    expires = utcnow() + timedelta(minutes=rwh.config['SESSION_DURATION'])
                    login_redirect_response.set_cookie('session_expires', int(expires.strftime('%s')))

                    return login_redirect_response
                else:
                    login_session.status = LoginSession.status_failed
                    db.session.add(login_session)
                    db.session.commit()

                    session.pop('session_id')
                    
                    initiation_failed_response = jsonify({'error': 'could not get bearer token'})
                    initiation_failed_response.set_cookie('session_expires', int(utcnow().strftime('%s')))
                    initiation_failed_response.status_code = status_code

                    return initiation_failed_response
            else:
                session.pop('session_id')

                session_not_found_response = jsonify({'error': 'no such session started'})
                session_not_found_response.set_cookie('session_expires', int(utcnow().strftime('%s')))
                session_not_found_response.status_code = 404
                
                return session_not_found_response
        if (login_session.status == LoginSession.status_active):
            return redirect(url_for('authentication.active'))
    else:
        session_id = str(uuid.uuid4())
        login_session = LoginSession(session_id) # default status='initiating'
        db.session.add(login_session)
        db.session.commit()

        app_id = rwh.config['APP_ID']
        app_url = rwh.config['APP_URL']
        authorization_redicrect_response = redirect("https://www.reddit.com/api/v1/authorize?client_id=%s&response_type=code&state=%s&redirect_uri=%s&duration=permanent&scope=identity,submit,edit" % (app_id, session_id, app_url))

        session['session_id'] = session_id
        expires = utcnow() + timedelta(minutes=rwh.config['SESSION_DURATION'])
        session_expires = int(expires.strftime('%s'))
        authorization_redirect_response.set_cookie('session_expires', session_expires)

        return authorization_redirect_response


def refresh_token(login_session):
    refresh_uri = 'https://www.reddit.com/api/v1/access_token'
    refresh_post_data = {
      'grant_type': 'refresh_token',
      'refresh_token': login_session.refresh_token
    }

    refresh_result, status_code = token_request(refresh_uri, refresh_post_data)

    if (status_code == 200):
        login_session.token = refresh_result.get('access_token')
        expires_in = refresh_result_data.get('expires_in')
        login_session.token_expires = utcnow() + timedelta(seconds=expires_in)

    return status_code


@login.route('/active', strict_slashes=False)
def active():
    login_session, session_id = get_login_session()
    if login_session and (login_session.status == LoginSession.status_active):
        time_now = utcnow()
        login_session.last_active = time_now

        status_code = 200
        if (time_now > login_session.token_expires):
            status_code = refresh_token(login_session)

        db.session.add(login_session)
        db.session.commit()

        session['session_id']      = session_id

        expires = time_now + timedelta(minutes=rwh.config['SESSION_DURATION'])
        session_expires = int(expires.strftime('%s')) # session_expires cookie

        if (status_code == 200):
            refresh = int(login_session.token_expires.strftime('%s'))
            session_refreshed_response = jsonify({'session': session_id,
                                                  'status': LoginSession.status_active,
                                                  'refresh': refresh})
            session_refreshed_response.set_cookie('session_expires', session_expires)
            return session_refreshed_response
        else:
            refresh_failed_response = jsonify({'error': 'could not refresh token'})
            refresh_failed_response.set_cookie('session_expires', session_expires)
            refresh_failed_response.status_code = status_code
            return refresh_failed_response
    else:
        return redirect(url_for('authentication.reddit_login'))


def revoke_token(login_session):
    token = login_session.token
    
    revoke_uri  = 'https://www.reddit.com/api/v1/revoke_token'
    revoke_post_data = {
      'token': token
    }

    revoke_result, status_code = token_request(revoke_uri, revoke_post_data)

    return status_code


@login.route('/logout', strict_slashes=False)
def logout():
    time_now = int(utcnow().strftime('%s')) # "session_expires" cookie value
    if ('session_id' in session):
        login_session, session_id = get_login_session()
        if login_session:
            if (login_session.status == LoginSession.status_active):
                revoke_status = revoke_token(login_session)
                if (revoke_status != 204):
                    revoke_failed_response = jsonify({'error': 'could not revoke token'})
                    revoke_failed_response.set_cookie('session_expires', time_now)
                    revoke_failed_response.status_code = revoke_status
                    return revoke_failed_response

                login_session.status = LoginSession.status_unlogged
                db.session.add(login_session)
                db.session.commit()

                session_unlogged_response = jsonify({'session': session_id,
                                                     'status': LoginSession.status_unlogged})
                session_unlogged_response.set_cookie('session_expires' time_now)
                session_unlogged_response.status_code = 200
                return session_unlogged_response
            else:
                session_invalid_response = jsonify({'session': session_id,
                                                    'status': login_session.status})
                session_invalid_response.set_cookie('session_expires' time_now)
                session_invalid_response.status_code = 200
                return session_invalid_response
        else:
            session_not_found_response = jsonify({'session': session_id,
                                                  'error': 'session not found'})
            session_not_found_response.set_cookie('session_expires', time_now)
            session_not_found_response.status_code = 404
            return session_not_found_response
    else:
        missing_session_id_response = jsonify({'error': 'missing session_id'})
        missing_session_id_response.set_cookie('session_expires', time_now)
        missing_session_id_response.status_code = 400
        return missing_session_id_response
