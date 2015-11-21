import os

class Config(object):
    CSRF_ENABLED     = True
    CSRF_SESSION_KEY = os.environ['SESSION_KEY']
    SECRET_KEY       = os.environ['COOKIES_KEY']

    db_host = os.environ['DB_HOST']
    db_name = os.environ['DB_NAME']
    db_user = os.environ['DB_USER']
    db_pass = os.environ['DB_PASS']
    SQLALCHEMY_DATABASE_URI = "postgresql://%s:%s@%s/%s" % (db_user, db_pass,
                                                            db_host, db_name)


class Production(Config):
    DEBUG       = False
    TESTING     = False
    DEVELOPEMNT = False

class Staging(Config):
    DEBUG       = True
    TESTING     = False
    DEVELOPEMNT = True

class Development(Config):
    DEBUG       = False
    TESTING     = False
    DEVELOPEMNT = True

class Testing(Config):
    DEBUG       = False
    TESTING     = True
    DEVELOPEMNT = False
