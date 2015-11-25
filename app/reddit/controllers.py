from flask import Blueprint, render_template

from app import rwh

"""
The blueprint for hadling URL's under the /reddit/* path.
These paths are to be used for rendering client-side files handling reddit API.
"""
reddit_blueprint = Blueprint('reddit', __name__, url_prefix='/reddit')

@reddit_blueprint.route('/client.js', strict_slashes=False)
def reddit_client_js():
    """
    Renders the client JS code that deals with Reddit API.
    This is not static since it may contain parts that depend on the app config.
    """
    user_agent_string = rwh.config['APP_USER_AGENT_CLIENT']
    app_url_string    = rwh.config['APP_URL']
    return render_template('reddit/client.js', user_agent=user_agent_string, app_url=app_url_string)
