import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from dotenv import load_dotenv

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
mail = Mail()

def create_app():
    """Application Factory"""

    # Load environment variables from .env file
    load_dotenv()

    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    @app.context_processor
    def inject_config():
        return dict(config=app.config)

    # 🔁 Load config from environment variable (default to dev)
    config_name = os.getenv('FLASK_CONFIG', 'config.dev')
    app.config.from_object(config_name)
    app.config['FLASK_CONFIG'] = config_name

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
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
