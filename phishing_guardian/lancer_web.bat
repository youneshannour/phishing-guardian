@echo off
call venv\Scripts\activate.bat
uvicorn web_phishing_guardian:app --reload
