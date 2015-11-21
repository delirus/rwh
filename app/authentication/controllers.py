import uuid
from datetime import timedelta
from datetime.datetime import utcfromtimestamp as utc
from datetime.datetime import utcnow as utcnow
from urllib.parse import urlencode
from urllib.request import Request as client_http_request
from urllib.request import HTTPBasicAuthHandler() as http_basic_auth_handler
from urllib.request import build_opener, install_opener, urlopen
from flask import Blueprint, request, render_template, redirect, session, url_for, jsonify

from app import db, rwh

from app.login.models import LoginSession

login = Blueprint('authentication', __name__, url_prefix='/authentication')

def get_login_session():
    login_session = None
    session_id    = session.get('session_id')
    if session_id:
        login_session = LoginSession.query.filer_by(id=session_id).first()
    return login_session, session_id

def authenticated(call):
    def authenticated_call():
        login_session, session_id = get_login_session()
        if login_session and (login_session.status == LoginSession.status_open):
            call()
        else:
            redirect(url_for('authentication.login'))
    return authenticated_call

@login.route('/login', strict_slashes=False)
def reddit_login():
    login_session, session_id = get_login_session()
    if login_session:
        if (login_session.status == LoginSession.status_initiating):
            # TODO parse parameters, retrieve token and save in login session
        if (login_session.status == LoginSession.status_open):
            redirect(url_for('authentication.active'))
    else:
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
        login_session = LoginSession(session_id) # status = 'init' by default
        db.session.add(login_session)
        db.session.commit()
        app_id = rwh.config.app_id
        redirect("https://www.reddit.com/api/v1/authorize?client_id=%s&response_type=code&state=%s&redirect_uri=https://aoiy.eu/rwh/authentication/login&duration=permanent&scope=identity,submit,edit" % (app_id, session_id))

def refresh_token(login_session):
    refresh_uri = 'https://www.reddit.com/api/v1/access_token'
    refresh_data = urlencode({
      'grant_type': 'refresh_token',
      'refresh_token': login_session.refresh_token
    }).encode('utf-8')
    refresh_request = client_http_request(refresh_uri,
                                          method='POST',
                                          data=refresh_data)
    refresh_request.add_header('User-Agent', rwh.config.app_user_agent)
    refresh_request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    authenticator = http_basic_auth_handler()
    authenticator.add_password(
      uri=refresh_uri,
      user=rwh.config.app_id,
      password=''
    )
    authenticated_opener = build_opener(authenticator)
    install_opener(authenticated_opener)
    refresh_result = urlopen(refresh_request)
    refresh_code   = refresh_result.getcode()
    refresh_token  = None
    if (result_code == 200):
        refresh_result_data = json.load(refresh_result)
        login_session.token = refresh_result_data.access_token
        login_session.token_expires = utc(refresh_result_data.expires_in)
        login_session.refresh_token = refresh_result_data.refresh_token
        refresh_token = login_session.token
    return refresh_token, refresh_code

@login.route('/active', strict_slashes=False)
def active():
    login_session, session_id = get_login_session()
    if login_session and (login_session.status == LoginSession.status_open):
        token       = login_session.token
        status_code = 200
        time_now = utcnow()
        login_session.last_active = time_now
        session_end = time_now + timedelta(minutes=rwh.config.session_duration)
        if (session_end > login_session.token_expires):
            token, status_code = refresh_token(login_session)
        if (status_code == 200):
            db.session.add(login_session)
            db.session.commit()
            expration = int(login_session.token_expires.strftime('%s'))
            return jsonify({'token': token, 'expires': expiration}), 200
        else:
            return None, status_code
    else:
        redirect(url_for('authentication.login'))

@login.route('/logout', strict_slashes=False)
def logout():
    if ('session_id' in session):
        session.pop('session_id')
        login_session, session_id = get_login_session()
        if login_session:
            db.session.delete(login_session)
            db.session.commit()
            # TODO: manually de-register session
    return None, 200
