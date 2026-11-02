@echo off
REM Double-click this file (Windows). It prepares everything and starts the app.
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install it from python.org and tick "Add python.exe to PATH".
  pause & exit /b 1
)

if not exist venv (
  echo Creating virtual environment...
  python -m venv venv || goto :fail
)
call venv\Scripts\activate.bat

echo Installing requirements...
pip install -q -r requirements.txt || goto :fail

if not exist instance mkdir instance
if not exist instance\admin_created.flag (
  call flask --app wsgi init-db || goto :fail
  echo.
  echo === Create the admin account for the SOC console ===
  echo Username will be: admin   (password: at least 10 characters)
  call flask --app wsgi create-admin --username admin || goto :fail
  echo done> instance\admin_created.flag
)

REM Short ban so you can test quickly. Remove this line to use the default 15 minutes.
set BASE_BAN_SECONDS=60

echo.
echo  User portal (honeypot) : http://127.0.0.1:5000/login
echo  SOC admin console      : http://127.0.0.1:5000/admin/login
echo.
flask --app wsgi run
pause
exit /b 0

:fail
echo.
echo Something failed. Copy the message above and send it to your teammate.
pause
exit /b 1
