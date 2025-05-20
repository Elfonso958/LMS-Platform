@echo off
echo 🔧 Starting LMS Platform in DEVELOPMENT mode...

:: 1) Tell Flask to use your factory and dev config
set FLASK_APP=app:create_app
set FLASK_ENV=development
set FLASK_CONFIG=config.dev

:: 2) Dev database & secrets
set DATABASE_URI=mysql+mysqldb://root:7frzqt6n@localhost/lms_test
set SECRET_KEY=my-dev-secret-key
set MAIL_USERNAME=jayden_beck01@xtra.co.nz
set MAIL_PASSWORD=200102489Mac!
set MAIL_DEFAULT_SENDER=jayden_beck01@xtra.co.nz

:: 3) Activate your venv
call venv\Scripts\activate.bat

:: 4) Make sure Python sees your project root
set PYTHONPATH=%CD%

:: 6) Finally, launch your app
python app\main.py
