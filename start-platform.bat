@echo off
echo Starting Cyber Guard IQ...
cd backend

:: Check if nodemon is available, fall back to plain node
where nodemon >nul 2>&1
if %errorlevel% == 0 (
    echo Using nodemon for hot-reload...
    start "" http://localhost:3000
    npm.cmd run dev
) else (
    echo nodemon not found, using node...
    start "" http://localhost:3000
    npm.cmd run start
)
pause
