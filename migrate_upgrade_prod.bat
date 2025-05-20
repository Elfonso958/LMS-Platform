@echo off
REM --------------------------------------------------
REM migrate_upgrade.bat
REM Usage: migrate_upgrade.bat [dev]
REM --------------------------------------------------

setlocal

REM 1) Choose environment
if /I "%1"=="prod" (
    echo 🔄 Running migrations for PRODUCTION...
    set "FLASK_ENV=production"
    set "FLASK_CONFIG=config.prod"
)

REM 2) Point Flask at your factory
set "FLASK_APP=app:create_app"

REM 3) Activate virtualenv
call venv\Scripts\activate.bat

REM 4) Ensure your app code is on PYTHONPATH
set "PYTHONPATH=%CD%"

REM 5) Autogenerate a new revision
flask db stamp

REM 6) Autogenerate a new revision
flask db migrate -m "Auto schema migration"

REM 7) Apply all pending migrations
flask db upgrade

REM 8) Final message (escape the & so Windows won’t split the command)
echo ✅ Migrations ^& upgrades complete for %FLASK_ENV%!

endlocal
pause
