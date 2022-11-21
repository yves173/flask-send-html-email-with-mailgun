from flask_smorest import Blueprint,abort
from flask.views import MethodView
from schemas import UserSchema
from models import UserModel
from db import db
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import create_access_token,get_jwt,create_refresh_token,get_jwt_identity,jwt_required
from blocklist import BLOCKLIST
import requests
import os
from dotenv import load_dotenv
import jinja2


load_dotenv()

blp=Blueprint('users',__name__,description='Operation on the Users')

@blp.route('/register')
class RegisterUser(MethodView):

    @blp.arguments(UserSchema)
    def post(self,userData):
        user=UserModel( username=userData['username'], password=pbkdf2_sha256.hash(userData['password']) )
        try:
            db.session.add(user)
            db.session.commit()
            return {'message':'user successfully created'},201
        except:
            abort(500,message='an error happen while creating a user')



@blp.route('/user/<int:user_id>')
class Users(MethodView):

    @blp.response(200,UserSchema)
    def get(self,user_id):
        user=UserModel.query.get_or_404(user_id)
        return user

    def delete(self,user_id):
        user=UserModel.query.get_or_404(user_id)
        try:
            db.session.delete(user)
            db.session.commit()
            return {'message':'user is successfully deleted'}
        except:
            abort(500,message='an error happen while deleting a user ')



@blp.route('/login')
class UserLogin(MethodView):

    @blp.arguments(UserSchema)
    def post(self,userData):
        user=UserModel.query.filter(UserModel.username==userData['username']).first()
        if user and pbkdf2_sha256.verify(userData['password'],user.password):
            access_tkn=create_access_token(identity= user.user_id,fresh=True)
            refresh_tkn=create_refresh_token(identity=user.user_id)
            return {'access_token':access_tkn,'refresh_token':refresh_tkn},200

        abort(401,message='invalid credentials')


@blp.route('/logout')
class UserLogout(MethodView):

    def post(self):
        jwt=get_jwt()['jti']
        BLOCKLIST.add(jwt)
        return {'message':'user successfully logout'}


@blp.route('/refresh')
class UserRefresh(MethodView):

    # only refresh token can access this endpoint
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_tkn=create_access_token(identity=current_user,fresh=True)
        return {'new_access_token':new_tkn},200



@blp.route('/sendmail')
class UserSendMail(MethodView):

    def post(self):

        send_simple_message()

        return {'message':'email is successfully sent'}



template_loader = jinja2.FileSystemLoader("templates")
template_env = jinja2.Environment(loader=template_loader)


def render_template(template_filename, **context):
    return template_env.get_template(template_filename).render(**context)


def send_simple_message():
    return requests.post(
        f"https://api.mailgun.net/v3/{os.getenv('MAILGUN_DOMAIN')}/messages",
        auth=("api", f"{os.getenv('MAILGUN_API_KEY')}"),
        data={"from": f"ABCD EFG <mailgun@{os.getenv('MAILGUN_DOMAIN')}>",
            "to": ["ex@gmail.com"],
            "subject": "Hello HAlo",
            "text": "Testing some Mailgun awesomness!",
            "html":render_template("email/email.html",username='yves Kwizera')
            })