@echo off
REM Script to deploy the project to GitHub

REM Check if git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Git is not installed. Please install Git first.
    exit /b 1
)

REM Check if we're in a git repository
if not exist ".git" (
    echo Initializing Git repository...
    git init
)

REM Add all files
echo Adding files to Git...
git add .

REM Commit changes
echo Committing changes...
git commit -m "Deploy project to GitHub"

REM Check if remote repository is set
git remote get-url origin >nul 2>&1
if %errorlevel% neq 0 (
    echo Please set your GitHub repository URL:
    echo git remote add origin https://github.com/yourusername/your-repo-name.git
    echo.
    echo Then push with:
    echo git push -u origin main
) else (
    echo Pushing to GitHub...
    git push -u origin main
)

echo Deployment script completed!
echo Remember: This application requires two continuously running services:
echo 1. main.py - The main bot service
echo 2. web_panel.py - The Flask web interface
echo.
echo For full functionality, deploy to a traditional server or cloud platform.