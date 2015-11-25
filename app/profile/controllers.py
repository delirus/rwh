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
from flask import Blueprint, request, session, make_response, render_template, flash, redirect, url_for, jsonify

from app import db, rwh
from app.auth.controllers import authenticated, get_login_session

"""
The blueprint for hadling URL's under the /profile/* path.
These paths are to be used for active user settings.
"""
profile_blueprint = Blueprint('profile', __name__, url_prefix='/profile')

@profile_blueprint.route('/', strict_slashes=False)
@authenticated
def settings():
    """
    what's up, doc?
    """
    login_session, session_id = get_login_session()
    user_agent_string = rwh.config['APP_USER_AGENT_CLIENT']
    return render_template('profile/settings.html', token=login_session.token, user_agent=user_agent_string)
