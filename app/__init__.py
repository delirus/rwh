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

from app.authentication.controllers import login
rwh.register_blueprint(login)


if __name__ == '__main__':
    rwh.run()
