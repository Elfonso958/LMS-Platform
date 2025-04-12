import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
mail = Mail()  # Instantiate the Mail class

def create_app():
    """Application Factory"""
    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    # Email Configuration
    app.config['MAIL_SERVER'] = 'send.xtra.co.nz'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.config['MAIL_USERNAME'] = 'jayden_beck01@xtra.co.nz'
    app.config['MAIL_PASSWORD'] = '200102489Mac!'
    app.config['MAIL_DEFAULT_SENDER'] = 'jayden_beck01@xtra.co.nz'
    app.config['BASE_URL'] = 'http://127.0.0.1:5000/'
    
    # Database Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://root:7frzqt6n@127.0.0.1:3306/lms_test'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Secret key for sessions
    app.config['SECRET_KEY'] = 'my-very-secret-key'
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['REMEMBER_COOKIE_SECURE'] = False
    app.config['CURRENT_TEMPLATE_VERSION'] = 2


    # Initialize plugins
    db.init_app(app)
    mail.init_app(app)  # Correctly initialize the mail extension
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Define upload folder for course PowerPoints
    upload_folder = os.path.join(os.getcwd(), 'Course_Powerpoints')
    os.makedirs(upload_folder, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_folder

    # Register models (imported here to avoid circular imports)
    with app.app_context():
        from . import models

    return app




