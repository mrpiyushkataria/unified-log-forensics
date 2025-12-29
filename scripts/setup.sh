#!/bin/bash

# Unified Log Forensics Platform Setup Script

set -e

echo "🚀 Setting up Unified Log Forensics Platform..."

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
if [[ $(echo "$PYTHON_VERSION 3.9" | awk '{print ($1 < $2)}') -eq 1 ]]; then
    echo "❌ Python 3.9+ is required. Found: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data reports logs/samples web/static web/templates

# Initialize database
echo "💾 Initializing database..."
python -c "
from app.models.database import init_db
init_db()
"

# Download sample logs for testing
echo "📊 Downloading sample logs..."
curl -s -o logs/samples/nginx_access.log \
    https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/nginx_logs/nginx_logs

# Create default config if not exists
if [ ! -f config.yaml ]; then
    echo "⚙️ Creating default configuration..."
    cp config.example.yaml config.yaml
fi

# Set permissions
echo "🔐 Setting permissions..."
chmod +x scripts/*.sh

echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Review config.yaml for your environment"
echo "2. Test with sample logs: python -m app.main analyze logs/samples/nginx_access.log"
echo "3. Start web interface: python -m app.main web"
echo "4. For production: docker-compose up -d"
echo ""
echo "📚 Documentation: https://github.com/yourusername/unified-log-forensics"
