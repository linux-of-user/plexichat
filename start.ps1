# NetLink Startup Script for Windows (PowerShell)
# Government-Level Secure Communication Platform

Write-Host "🚀 Starting NetLink v3.0..." -ForegroundColor Cyan
Write-Host "Government-Level Secure Communication Platform" -ForegroundColor Green
Write-Host ""

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not found. Please install Python 3.8+ from https://python.org" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if virtual environment exists
if (Test-Path "venv") {
    Write-Host "✅ Virtual environment found" -ForegroundColor Green
    Write-Host "🔄 Activating virtual environment..." -ForegroundColor Yellow
    & "venv\Scripts\Activate.ps1"
} else {
    Write-Host "⚠️  Virtual environment not found. Creating one..." -ForegroundColor Yellow
    python -m venv venv
    & "venv\Scripts\Activate.ps1"
    Write-Host "✅ Virtual environment created and activated" -ForegroundColor Green
}

# Install/update dependencies
Write-Host "📦 Installing/updating dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet

# Create necessary directories
Write-Host "📁 Creating necessary directories..." -ForegroundColor Yellow
$directories = @("data", "logs", "config", "backups", "backups/shards", "backups/metadata")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  Created: $dir" -ForegroundColor Gray
    }
}

# Move databases to data directory if they exist in root
$databases = @("netlink.db", "rate_limits.db")
foreach ($db in $databases) {
    if (Test-Path $db) {
        Move-Item $db "data/$db" -Force
        Write-Host "  Moved $db to data/" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "🌟 NetLink is starting..." -ForegroundColor Cyan
Write-Host "📍 Web Interface: http://localhost:8000" -ForegroundColor Yellow
Write-Host "📍 Admin Panel: http://localhost:8000/admin" -ForegroundColor Yellow
Write-Host "📍 Documentation: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "📍 Setup Wizard: http://localhost:8000/setup" -ForegroundColor Yellow
Write-Host "📍 Utilities: http://localhost:8000/utils" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Red
Write-Host ""

# Start the application
try {
    python -m uvicorn src.netlink.app.main:app --host 0.0.0.0 --port 8000 --reload
} catch {
    Write-Host ""
    Write-Host "❌ Failed to start NetLink. Check the error above." -ForegroundColor Red
    Write-Host "💡 Try running: pip install -r requirements.txt" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
}
