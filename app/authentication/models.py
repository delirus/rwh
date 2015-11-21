from app import db

class LoginSession(db.Model):
    status_initiating = 'init'
    status_open       = 'open'

    id          = db.Column(db.String(36), primary_key=True)
    status      = db.Column(db.String(4))
    username    = db.Column(db.String(256), default=None)
    last_active = db.Column(db.DateTime, default=db.func.current_timestamp(),
                                         onupdate=db.func.current_timestamp())

    def __initialize__(self, session_id):
        self.id     = session_id
        self.status = self.status_initiating
    
    def __repr__(self):
        return "<LoginSession %s>" % str(self.id)
