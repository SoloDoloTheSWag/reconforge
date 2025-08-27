#!/bin/bash

# ReconForge Web Interface Startup Script
# This script automatically activates the virtual environment and starts the web interface

echo "🚀 Starting ReconForge Web Interface..."
echo "📂 Project Directory: $(pwd)"

# Check if we're in the right directory
if [[ ! -f "reconforge.py" ]]; then
    echo "❌ Error: reconforge.py not found. Please run this script from the ReconForge directory."
    exit 1
fi

# Check if virtual environment exists, create if needed
if [[ ! -d "venv" ]]; then
    echo "🔧 Virtual environment not found. Creating one..."
    python3 -m venv venv
    if [[ $? -ne 0 ]]; then
        echo "❌ Error: Failed to create virtual environment. Please install python3-venv:"
        echo "   sudo apt install python3-venv"
        exit 1
    fi
    echo "✅ Virtual environment created successfully"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Verify activation
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Virtual environment activated: $(basename $VIRTUAL_ENV)"
else
    echo "❌ Error: Failed to activate virtual environment"
    exit 1
fi

# Check Python and dependencies
echo "🐍 Python version: $(python --version)"
echo "📦 Checking dependencies..."

# Check if main dependencies are installed
if ! python -c "import fastapi, uvicorn, jinja2" 2>/dev/null; then
    echo "🔧 Installing dependencies..."
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        if [[ $? -ne 0 ]]; then
            echo "❌ Error: Failed to install dependencies"
            echo "   Please manually run: pip install -r requirements.txt"
            exit 1
        fi
        echo "✅ Dependencies installed successfully"
    else
        echo "❌ Error: requirements.txt not found"
        exit 1
    fi
else
    echo "✅ All dependencies found"
fi
echo ""
echo "🌐 Starting ReconForge Web Interface..."
echo "📡 URL: http://localhost:8000"
echo "🛑 Press Ctrl+C to stop"
echo ""

# Start the web interface
python reconforge.py web --host 0.0.0.0 --port 8000