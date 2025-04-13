@echo off
echo Switching to DEV environment...

set FLASK_APP=app
set FLASK_ENV=development
set FLASK_CONFIG=config.dev

set DATABASE_URI=mysql+mysqldb://root:7frzqt6n@localhost/lms_test
set SECRET_KEY=my-dev-secret-key
set MAIL_USERNAME=jayden_beck01@xtra.co.nz
set MAIL_PASSWORD=200102489Mac!
set MAIL_DEFAULT_SENDER=jayden_beck01@xtra.co.nz

flask run
