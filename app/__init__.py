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

from app.auth.controllers import auth_blueprint
rwh.register_blueprint(auth_blueprint)

from app.profile.controllers import profile_blueprint
rwh.register_blueprint(profile_blueprint)


if __name__ == '__main__':
    rwh.run()
