import os

class Config(object):
    CSRF_ENABLED = True
    db_path = os.environ['DB_PATH']
    db_user = os.environ['DB_USER']
    db_pass = os.environ['DB_PASS']

class ProductionConfig(Config):
    DEBUG       = False
    TESTING     = False
    DEVELOPEMNT = False

class StagingConfig(Config):
    DEBUG       = True
    TESTING     = False
    DEVELOPEMNT = True

class DevelopmentConfig(Config):
    DEBUG       = False
    TESTING     = False
    DEVELOPEMNT = True

class TestingConfig(Config):
    DEBUG       = False
    TESTING     = True
    DEVELOPEMNT = False
