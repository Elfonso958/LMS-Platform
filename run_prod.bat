@echo off
echo 🚀 Starting LMS Platform in PRODUCTION mode...

:: Set production environment variables
set FLASK_ENV=production
set FLASK_APP=app:create_app
set DATABASE_URI=mysql+mysqldb://root:7frzqt6n@localhost/lms_prod
…

call venv\Scripts\activate.bat
set PYTHONPATH=%CD%

:: then launch
python app\main.py
