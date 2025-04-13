@echo off
cd C:\LMS-Platform
call venv\Scripts\activate.bat
git pull origin refactor/move-routes-from-main
pip install -r requirements.txt
taskkill /F /IM python.exe
start /b python main.py