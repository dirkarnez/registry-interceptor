@echo off
set PYTHON_DIR=%USERPROFILE%\Downloads\python-3.10.8-amd64-portable
set PATH=%PYTHON_DIR%;%PYTHON_DIR%\Scripts

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

set target=%USERPROFILE%\Downloads\cpp-registry-playground\cmake-build\cpp-registry-playground.exe

start "" %target%
python bb.py cpp-registry-playground.exe
pause
