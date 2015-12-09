from uuid import uuid4
from app import db

class LoginSession(db.Model):
    status_initiating = 'initiating'
    status_failed     = 'failed'
    status_active     = 'active'
    status_unlogged   = 'unlogged'
    status_expired    = 'expired'

    id            = db.Column(db.String(36),              primary_key=True)
    secret        = db.Column(db.String(36),              default=None)
    status        = db.Column(db.String(10),              default=None)
    username      = db.Column(db.String(65),              default=None)
    token         = db.Column(db.String(36),              default=None)
    token_expires = db.Column(db.DateTime(timezone=True), default=None)
    refresh_token = db.Column(db.String(36),              default=None)
    last_active   = db.Column(db.DateTime(timezone=True),
                              default=db.func.current_timestamp(),
                              onupdate=db.func.current_timestamp())

    def __init__(self, session_id):
        self.id     = session_id
        self.secret = str(uuid4())
        self.status = self.status_initiating
    
    def __repr__(self):
        return "<LoginSession %s>" % str(self.id)
