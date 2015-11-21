import os
from datetime import timedelta
from flask import Flask, render_template, session
from flask.ext.sqlalchemy import SQLAlchemy

rwh = Flask(__name__)
 
rwh.config.from_object(os.environ['APP_SETTINGS'])

db = SQLAlchemy(rwh)

@rwh.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404

@rwh.before_request
def make_session_permanent():
    session.permenent = True
    rwh.permanent_session_lifetime = timedelta(minutes=rwh.config.session_duration)

from app.authentication.controllers import login
rwh.register_blueprint(login)

db.create_all()

if __name__ == '__main__':
    rwh.run()
