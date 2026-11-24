@echo off
REM Run from an Administrator terminal. Creates the venv on first run.
cd /d "%~dp0backend"
if not exist .venv (
  py -m venv .venv
  call .venv\Scripts\activate
  pip install -r requirements.txt
) else (
  call .venv\Scripts\activate
)
echo Open http://127.0.0.1:5000 in your browser
py app.py
