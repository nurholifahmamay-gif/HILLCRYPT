@echo off
cd /d "%~dp0"
echo Installing HILLCRYPT dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
echo.
echo Installation finished. Double-click RUN_HILLCRYPT.bat to start the app.
pause
