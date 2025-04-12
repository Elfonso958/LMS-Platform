@echo off
echo Switching to DEV environment...
set FLASK_APP=app
set FLASK_ENV=development
set FLASK_CONFIG=config.dev
python app/main.py
