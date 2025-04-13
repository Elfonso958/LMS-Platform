@echo off
echo Switching to DEV environment...

set FLASK_APP=app
set FLASK_ENV=development
set FLASK_CONFIG=config.dev

:: Environment variables your config file needs
set DATABASE_URI=mysql+mysqldb://root:7frzqt6n@localhost/lms_prod
set SECRET_KEY=my-dev-secret-key
set MAIL_USERNAME=your-email@example.com
set MAIL_PASSWORD=your-email-password
set MAIL_DEFAULT_SENDER=your-email@example.com

flask run
