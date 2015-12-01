from os import environ
from flask import Flask, render_template, session
rwh = Flask(__name__)
rwh.config.from_object(environ['APP_SETTINGS'])

@rwh.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


from flask.ext.sqlalchemy import SQLAlchemy
db = SQLAlchemy(rwh)


from app.auth.controllers import auth_blueprint
rwh.register_blueprint(auth_blueprint)

from app.profile.controllers import profile_blueprint
rwh.register_blueprint(profile_blueprint)


if __name__ == '__main__':
    rwh.run()
