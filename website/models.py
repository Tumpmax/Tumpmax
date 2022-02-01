from datetime import datetime
from enum import unique
from sqlalchemy.orm import backref
from . import db
from flask_login import UserMixin



class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    pw_attempt1 = db.Column(db.Integer)
    pw_attempt2 = db.Column(db.Integer)
    pw_attempt3 = db.Column(db.Integer)

class Crypto(db.Model):
    __tablename__ = 'cryptos'
    id = db.Column(db.Integer, primary_key=True)
    crypto = db.Column(db.String(20), nullable=False)
    crypto_data = db.Column(db.Float(150), nullable=False)
    datestp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    

