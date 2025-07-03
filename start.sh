#!/bin/bash
# NetLink Startup Script for Linux/macOS
# Government-Level Secure Communication Platform

echo "🚀 Starting NetLink v3.0..."
echo "Government-Level Secure Communication Platform"
echo ""

# Check if Python is installed
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    echo "✅ Python found: $(python3 --version)"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    echo "✅ Python found: $(python --version)"
else
    echo "❌ Python not found. Please install Python 3.8+ from https://python.org"
    read -p "Press Enter to exit"
    exit 1
fi

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "✅ Virtual environment found"
    echo "🔄 Activating virtual environment..."
    source venv/bin/activate
else
    echo "⚠️  Virtual environment not found. Creating one..."
    $PYTHON_CMD -m venv venv
    source venv/bin/activate
    echo "✅ Virtual environment created and activated"
fi

# Install/update dependencies
echo "📦 Installing/updating dependencies..."
pip install -r requirements.txt --quiet

# Create necessary directories
echo "📁 Creating necessary directories..."
directories=("data" "logs" "config" "backups" "backups/shards" "backups/metadata")
for dir in "${directories[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        echo "  Created: $dir"
    fi
done

# Move databases to data directory if they exist in root
databases=("netlink.db" "rate_limits.db")
for db in "${databases[@]}"; do
    if [ -f "$db" ]; then
        mv "$db" "data/$db"
        echo "  Moved $db to data/"
    fi
done

echo ""
echo "🌟 NetLink is starting..."
echo "📍 Web Interface: http://localhost:8000"
echo "📍 Admin Panel: http://localhost:8000/admin"
echo "📍 Documentation: http://localhost:8000/docs"
echo "📍 Setup Wizard: http://localhost:8000/setup"
echo "📍 Utilities: http://localhost:8000/utils"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the application
if command -v uvicorn &> /dev/null; then
    uvicorn src.netlink.app.main:app --host 0.0.0.0 --port 8000 --reload
else
    $PYTHON_CMD -m uvicorn src.netlink.app.main:app --host 0.0.0.0 --port 8000 --reload
fi

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Failed to start NetLink. Check the error above."
    echo "💡 Try running: pip install -r requirements.txt"
    read -p "Press Enter to exit"
fi
