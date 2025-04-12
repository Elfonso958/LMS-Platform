@echo off
echo Switching to PROD environment...
set FLASK_APP=app
set FLASK_ENV=production
set FLASK_CONFIG=config.prod
python app/main.py
