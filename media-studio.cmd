@echo off
rem Start Kusylit's Studio (image / edit / video) and open the page.
rem If the server is already answering on 8790, only the browser is opened.
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8790/' -TimeoutSec 1; if ($r.StatusCode -eq 200) { exit 0 } } catch {}; exit 1"
if not errorlevel 1 goto open
where python >nul 2>&1
if errorlevel 1 (
  start "" py -3 "%~dp0media_studio.py"
) else (
  start "" python "%~dp0media_studio.py"
)
:open
start "" http://127.0.0.1:8790/
