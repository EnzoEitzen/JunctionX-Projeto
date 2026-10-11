@echo off
rem run_all.bat - runs the whole QuantumTrace pipeline, then opens the dashboard.
rem
rem Usage (from the project folder, or just double-click it):
rem     run_all.bat            run everything
rem     run_all.bat replace    the MongoDB collection will hold ONLY this run's findings

cd /d "%~dp0"

set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"

if not exist "output" mkdir "output"

set "CLASSIFIER_FLAGS="
if /I "%~1"=="replace" set "CLASSIFIER_FLAGS=--replace"

echo.
echo === 1/5 Network analyzer ===
%PY% .\network_analyzer.py .\data\network-capture .\output\network_analyzer_output.json
if errorlevel 1 goto failed

echo.
echo === 2/5 Config scanner ===
%PY% .\config_scanner.py .\data\cloud-posture .\output\config_scanner_output.json
if errorlevel 1 goto failed

echo.
echo === 3/5 Code scanner ===
%PY% .\code_scanner.py .\data\sample-repos .\output\code_scanner_output.json
if errorlevel 1 goto failed

echo.
echo === 4/5 Classifier ===
%PY% .\classifier.py .\output .\output\result.json %CLASSIFIER_FLAGS%
if errorlevel 1 goto failed

echo.
echo === 5/5 Dashboard ===
%PY% -m streamlit run .\app.py
if errorlevel 1 goto failed

goto :eof

:failed
echo.
echo A step failed (see the message above). Stopping.
pause
exit /b 1
