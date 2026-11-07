@echo off
rem Stop the WorkBuddy media studio (port 8790 only).
powershell -NoProfile -Command "$pids = Get-NetTCPConnection -LocalPort 8790 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | Where-Object { $_ -gt 0 }; foreach ($p in $pids) { Write-Host ('Stopping PID ' + $p + ' ...'); Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }"
echo Done.
