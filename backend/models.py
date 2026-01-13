from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(80),nullable=False)
    password = db.Column(db.String(120),nullable=False)


    