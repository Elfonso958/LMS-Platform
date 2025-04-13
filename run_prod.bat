@echo off
echo 🚀 Starting LMS Platform in PRODUCTION mode...

:: Set production environment variables
set FLASK_CONFIG=config.prod
set FLASK_APP=app:create_app()
set DATABASE_URI=mysql+mysqldb://root:7frzqt6n@localhost/lms_prod
set SECRET_KEY=your-very-secret-prod-key
set MAIL_USERNAME=your-email@example.com
set MAIL_PASSWORD=your-email-password
set MAIL_DEFAULT_SENDER=your-email@example.com

call venv\Scripts\activate.bat

python main.py
