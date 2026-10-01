@echo off
REM Starts the pipeline (log puller + detection engine) and the dashboard.
cd /d "%~dp0siem"
if exist ..\venv\Scripts\activate.bat call ..\venv\Scripts\activate.bat
start "Honeytrap pipeline" cmd /k python pipeline.py
python app.py
