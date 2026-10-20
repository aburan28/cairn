@echo off
setlocal
rem Local-only by default. The node console owns the process: closing it stops Cairn.
if not defined LOCALAPPDATA (
  echo Cairn could not find your local application-data folder.
  pause
  exit /b 1
)
set "CAIRN_WINDOWS_DATA=%LOCALAPPDATA%\Cairn"
if not exist "%CAIRN_WINDOWS_DATA%" mkdir "%CAIRN_WINDOWS_DATA%"
powershell.exe -NoProfile -Command "$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,8080); try{$l.Start();$l.Stop();exit 0}catch{Write-Host 'Cairn could not start because port 8080 is already in use. Close the existing node, or choose another port using the README.';exit 1}"
if errorlevel 1 (
  pause
  exit /b 1
)
rem Open the reader after a short delay while this window starts the node.
rem No script execution-policy changes, service installation or firewall changes.
start "Cairn reader" /min powershell.exe -NoProfile -Command "$u='http://localhost:8080/ui/'; for($i=0;$i -lt 60;$i++){try{if((Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 1).StatusCode -eq 200){Start-Process $u; exit 0}}catch{}; Start-Sleep -Seconds 1}; Write-Host 'The reader did not start. Check the Cairn node window.'"
echo Starting Cairn. Close this window to stop the node.
"%~dp0cairn.exe" --data-dir "%CAIRN_WINDOWS_DATA%" --root "%CAIRN_WINDOWS_DATA%" run --listen 127.0.0.1:0 --serve 127.0.0.1:8080 --no-mcp
if errorlevel 1 pause
