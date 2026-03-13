@echo off
echo Starting Cyber Guard IQ...

:: Check if nodemon is available (installed via npm install)
where nodemon >nul 2>&1
if %errorlevel% == 0 (
    echo Using nodemon for hot-reload...
    start "" http://localhost:3000
    npm.cmd run dev
) else (
    :: Install deps if node_modules is missing
    if not exist node_modules (
        echo Installing dependencies...
        npm.cmd install
    )
    start "" http://localhost:3000
    npm.cmd run start
)
pause
