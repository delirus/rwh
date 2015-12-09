import os 
from datetime import timedelta

class Config(object):
    APP_ID = os.environ['APP_ID']
    APP_URL = os.environ['APP_URL']
    APP_USER_AGENT_SERVER = "web-server_backend:RedditWriterHelper:github.com/delirus/rwh/tree/%s (by u/grepe)" % os.environ['APP_VERSION']
    APP_USER_AGENT_CLIENT = "in-browser_frontend:RedditWriterHelper:github.com/delirus/rwh/tree/%s (by u/grepe)" % os.environ['APP_VERSION']
    
    CSRF_ENABLED     = True
    CSRF_SESSION_KEY = os.environ['SESSION_KEY']
    SECRET_KEY       = os.environ['COOKIES_KEY']
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ['SESSION_DURATION']))
    SESSION_DURATION = os.environ['SESSION_DURATION']

    db_host = os.environ['DB_HOST']
    db_name = os.environ['DB_NAME']
    db_user = os.environ['DB_USER']
    db_pass = os.environ['DB_PASS']
    SQLALCHEMY_DATABASE_URI = "postgresql://%s:%s@%s/%s" % (db_user, db_pass,
                                                            db_host, db_name)

    SCHEDULER_PID = os.environ['SCHEDULER_PID']

    RWH_DATA = os.environ['RWH_DATA']

class Production(Config):
    DEBUG       = False
    TESTING     = False
    DEVELOPEMNT = False

class Staging(Config):
    DEBUG       = False
    TESTING     = False
    DEVELOPEMNT = True

class Development(Config):
    DEBUG       = True
    TESTING     = False
    DEVELOPEMNT = True

class Testing(Config):
    DEBUG       = False
    TESTING     = True
    DEVELOPEMNT = False
