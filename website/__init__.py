import os
from os import path
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from dotenv import load_dotenv

db = SQLAlchemy()
bcrypt = Bcrypt()

load_dotenv('config.env')

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = (f'sqlite:///' + os.environ.get('DB_NAME'))
    app.config['UPLOAD_FOLDER'] = os.environ.get('FOLDER')
    app.config['MAX_CONTENT_PATH'] = os.environ.get('MAX_CONTENT')
    db.init_app(app)
    bcrypt.init_app(app)
    

    from .views import views

    app.register_blueprint(views, url_prefix='/')

    from .models import Crypto
    from .models import User
    from .models import Crypto


    create_database(app)

    login_manager = LoginManager()
    login_manager.login_view = 'views.sign_up'
    login_manager.init_app(app)
    

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
 
    return(app)

def create_database(app):
    if not path.exists('website/' +  os.environ.get('DB_NAME')):
        db.create_all(app=app)
        print('Created Database')
