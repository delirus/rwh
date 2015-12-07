from os import environ
from flask import Flask, render_template, session
rwh = Flask(__name__)
rwh.config.from_object(environ['APP_SETTINGS'])

@rwh.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


from flask.ext.sqlalchemy import SQLAlchemy
db = SQLAlchemy(rwh)

from app.auth.util import start_periodic_cleanup
start_periodic_cleanup(db)


from app.auth.controllers import auth_blueprint
rwh.register_blueprint(auth_blueprint)

from app.profile.controllers import profile_blueprint
rwh.register_blueprint(profile_blueprint)


from flask.ext.assets import Bundle, Environment
bundles = {
    'error_css': Bundle('css/basic.css',
                        'css/error.css',
                        output='gen/error.css'),
    'error_js': Bundle('js/error.js',
                       output='gen/error.js')
}

assets = Environment(rwh)
assets.register(bundles)


if __name__ == '__main__':
    rwh.run()
