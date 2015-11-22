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
    authenticator.add_password(realm='reddit', uri=uri, user=rwh.config['APP_ID'], passwd='')
    authenticated_opener = build_opener(authenticator)

    request_result = authenticated_opener.open(token_request)

    status_code = request_result.getcode()
    if request_result:
        result_body = request_result.read().decode('utf-8')
        result_data = json.loads(result_body)
    else:
        resutl_data = None

    return result_data, status_code
    

def obtain_token(login_session, authorization_code):
    authorization_uri  = 'https://www.reddit.com/api/v1/access_token'
    authorization_data = {
      'grant_type':  'authorization_code',
      'code':         authorization_code,
      'redirect_uri': rwh.config['APP_URL']
    }

    authorization_data, status_code = token_request(authorization_uri,
                                                    authorization_data)

    if (status_code == 200):
        token         = authorization_data.get('access_token')
        expiration    = authorization_data.get('expires_in')
        refresh_token = authorization_data.get('refresh_token')

        login_session.status        = LoginSession.status_open
        login_session.token         = token
        login_session.token_expires = utc(expiration)
        login_session.refresh_token = refresh_token

        return token, expiration, 200
    else:
        return None, None, status_code


@login.route('/login', strict_slashes=False)
def reddit_login():
    login_session, session_id = get_login_session()
    if login_session:
        if (login_session.status == LoginSession.status_initiating):
            code  = request.args.get('code')
            state = request.args.get('state')
            if (state == session_id):
                token, expires, status_code = obtain_token(login_session, code)
                if (status_code == 200):
                    db.session.add(login_session)
                    db.session.commit()
                    expires = int(login_session.token_expires.strftime('%s'))
                    session['session_id'] = login_session.id
                    return jsonify({'token': token, 'expires': expires}), 200
                else:
                    return jsonify({'error': 'could not get bearer token'}), status_code
            else:
                return jsonify({'error': 'no such session started'}), 440
        if (login_session.status == LoginSession.status_open):
            return redirect(url_for('authentication.active'))
    else:
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
        login_session = LoginSession(session_id) # status = 'init' by default
        db.session.add(login_session)
        db.session.commit()
        app_id = rwh.config['APP_ID']
        app_url = rwh.config['APP_URL']
        return redirect("https://www.reddit.com/api/v1/authorize?client_id=%s&response_type=code&state=%s&redirect_uri=%s&duration=permanent&scope=identity,submit,edit" % (app_id, session_id, app_url))


def refresh_token(login_session):
    refresh_uri = 'https://www.reddit.com/api/v1/access_token'
    refresh_data = {
      'grant_type': 'refresh_token',
      'refresh_token': login_session.refresh_token
    }

    refresh_result_data, status_code = token_request(refresh_uri, refresh_data)

    refresh_token  = None
    if (status_code == 200):
        login_session.token = refresh_result_data.get('access_token')
        login_session.token_expires = utc(refresh_result_data.get('expires_in'))
        login_session.refresh_token = refresh_result_data.get('refresh_token')
        refresh_token = login_session.token
    return refresh_token, status_code


@login.route('/active', strict_slashes=False)
def active():
    login_session, session_id = get_login_session()
    if login_session and (login_session.status == LoginSession.status_open):
        token       = login_session.token
        status_code = 200
        time_now = utcnow()
        login_session.last_active = time_now
        session_end = time_now + timedelta(minutes=rwh.config['SESSION_DURATION'])
        if (session_end > login_session.token_expires):
            token, status_code = refresh_token(login_session)
        session['session_id'] = login_session.id
        if (status_code == 200):
            db.session.add(login_session)
            db.session.commit()
            expires = int(login_session.token_expires.strftime('%s'))
            return jsonify({'token': token, 'expires': expires}), 200
        else:
            return jsonify({'error': 'could not refresh token'}), status_code
    else:
        return redirect(url_for('authentication.reddit_login'))


def revoke_token(login_session):
    token = login_session.id
    
    revoke_uri  = 'https://www.reddit.com/api/v1/revoke_token'
    revoke_data = {
      'token': token
    }

    revoke_result, status_code = token_request(revoke_uri, revoke_data)


@login.route('/logout', strict_slashes=False)
def logout():
    if ('session_id' in session):
        session.pop('session_id')
        login_session, session_id = get_login_session()
        if login_session:
            revoke_token(login_session)
            db.session.delete(login_session)
            db.session.commit()
    return jsonify({'ok': 204}), 204
