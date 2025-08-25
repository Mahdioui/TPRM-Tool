@echo off
chcp 65001 >nul
echo 🚀 PCAP Security Analyzer - Deployment Script
echo ==============================================

REM Check if git is installed
git --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Git is not installed. Please install Git first.
    pause
    exit /b 1
)

REM Check if we're in a git repository
if not exist ".git" (
    echo 📁 Initializing Git repository...
    git init
    git add .
    git commit -m "Initial commit: PCAP Security Analyzer"
    echo ✅ Git repository initialized
) else (
    echo 📁 Git repository already exists
)

REM Check current git status
echo 📊 Current Git status:
git status --short

REM Ask user for GitHub repository URL
echo.
echo 🌐 Please provide your GitHub repository URL:
echo    Format: https://github.com/username/repository-name.git
set /p github_url="   GitHub URL: "

if "%github_url%"=="" (
    echo ❌ GitHub URL is required. Exiting.
    pause
    exit /b 1
)

REM Add remote origin
echo 🔗 Adding GitHub remote...
git remote add origin "%github_url%" 2>nul || git remote set-url origin "%github_url%"

REM Push to GitHub
echo 📤 Pushing to GitHub...
git branch -M main
git push -u origin main

if errorlevel 0 (
    echo ✅ Successfully pushed to GitHub!
) else (
    echo ❌ Failed to push to GitHub. Please check your credentials and try again.
    pause
    exit /b 1
)

echo.
echo 🎉 Deployment to GitHub completed successfully!
echo.
echo 📋 Next steps for Vercel deployment:
echo    1. Go to https://vercel.com
echo    2. Sign in with your GitHub account
echo    3. Click 'New Project'
echo    4. Import your GitHub repository
echo    5. Vercel will auto-detect Python configuration
echo    6. Click 'Deploy'
echo.
echo 🔧 Vercel will automatically:
echo    - Install Python dependencies from requirements.txt
echo    - Use the vercel.json configuration
echo    - Deploy your Flask application
echo.
echo 🌐 Your app will be available at: https://your-project.vercel.app
echo.
echo 📚 For more information, check the README.md file
echo.
echo 🚀 Happy deploying!
pause
