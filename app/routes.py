from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()  # Initialize the SQLAlchemy object

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:7frzqt6n@127.0.0.1:3306/lms_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)  # Bind SQLAlchemy to the app

    with app.app_context():
        from . import models  # Import models inside the app context

    return app
