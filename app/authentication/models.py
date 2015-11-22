from app import db

class LoginSession(db.Model):
    status_initiating = 'initiating'
    status_active     = 'active'
    status_unlogged   = 'unlogged'
    status_expired    = 'expired'

    id            = db.Column(db.String(36), primary_key=True)
    status        = db.Column(db.String(10))
    username      = db.Column(db.String(256), default=None)
    token         = db.Column(db.String(36), default=None)
    token_expires = db.Column(db.DateTime, default=None)
    refresh_token = db.Column(db.String(36), default=None)
    last_active   = db.Column(db.DateTime, default=db.func.current_timestamp(),
                                           onupdate=db.func.current_timestamp())

    def __init__(self, session_id):
        self.id     = session_id
        self.status = self.status_initiating
    
    def __repr__(self):
        return "<LoginSession %s>" % str(self.id)
