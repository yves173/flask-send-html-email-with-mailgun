from db import db

class UserModel(db.Model):
    __tablename__='users'

    user_id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),unique=True,nullable=False)
    password=db.Column(db.String(100),nullable=False)