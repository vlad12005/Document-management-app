from datetime import datetime

from blog.extensions import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60),nullable=False)



class UserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))
    accessible_users = db.relationship('User', secondary='user_file_access', backref='accessible_files')
    signature = db.Column(db.String(255))
    is_public = db.Column(db.Boolean, default=False)



class UserFile_2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='uploaded_files_2')
    is_public = db.Column(db.Boolean, default=False)


class UserFileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('user_file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(10), default='unread')
    type = db.Column(db.String(20), default='general')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    recipient = db.relationship('User', foreign_keys=[user_id], backref='notifications_received')
    sender = db.relationship('User', foreign_keys=[from_user_id], backref='notifications_sent')
