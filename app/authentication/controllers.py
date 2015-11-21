import uuid, datetime
from flask import Blueprint, request, render_template, redirect, session, url_for

from app import db, rwh

from app.login.models import LoginSession

login = Blueprint('authentication', __name__)

def get_login_session(cookie_session):
    login_session = None
    session_id    = cookie_session.get('session_id')
    if session_id:
        login_session = LoginSession.query.filer_by(id=session_id).first()
    return login_session, session_id

def authenticated(call):
    def authenticated_call():
        login_session, session_id = get_login_session(session)
        if login_session and (login_session.status == LoginSession.status_open):
            call()
        else:
            redirect(url_for('authentication.login'))
    return authenticated_call

@login.route('/login', strict_slashes=False)
def reddit_login():
    login_session, session_id = get_login_session(session)
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
        redirect("https://www.reddit.com/api/v1/authorize?client_id=%s&response_type=code&state=%s&redirect_uri=https://aoiy.eu/rwh/login&duration=permanent&scope=identity,submit,edit" % (app_id, session_id))

@login.route('/active', strict_slashes=False)
def active():
    login_session, session_id = get_login_session(session)
    if login_session and (login_session.status == LoginSession.status_open):
        login_session.last_active = datetime.utcnow()
        db.session.add(login_session)
        db.session.commit()
        # TODO: check if token expires within session, if yes, refresh it
        return None, 200
    else:
        redirect(url_for('authentication.login'))

@login.route('/logout', strict_slashes=False)
def logout():
    if ('session_id' in session):
        session.pop('session_id')
        login_session, session_id = get_login_session(session)
        if login_session:
            db.session.delete(login_session)
            db.session.commit()
            # TODO: manually de-register session
    return None, 200
