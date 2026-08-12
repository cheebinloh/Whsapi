@echo off
cd /d C:\xampp\htdocs\whatsapp_api
:loop
node --experimental-sqlite --env-file-if-exists=.env server.js >> server.log 2>&1
echo %date% %time% server exited, restarting in 5s >> server.log
timeout /t 5 /nobreak >nul
goto loop
