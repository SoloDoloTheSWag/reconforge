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

# Check if virtual environment exists
if [[ ! -d "venv" ]]; then
    echo "❌ Error: Virtual environment not found. Please run the installation first."
    exit 1
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

if ! python -c "import fastapi, uvicorn, jinja2" 2>/dev/null; then
    echo "❌ Error: Missing dependencies. Please install requirements:"
    echo "   pip install -r requirements.txt"
    exit 1
fi

echo "✅ All dependencies found"
echo ""
echo "🌐 Starting ReconForge Web Interface..."
echo "📡 URL: http://localhost:8000"
echo "🛑 Press Ctrl+C to stop"
echo ""

# Start the web interface
python reconforge.py web --host 0.0.0.0 --port 8000