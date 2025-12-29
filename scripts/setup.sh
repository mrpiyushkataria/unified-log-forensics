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
mkdir -p app/{core,models,ingestors,api,cli,utils,web/{static/{css,js,img},templates}}

# Create __init__.py files
echo "📝 Creating module structure..."
touch app/__init__.py
touch app/core/__init__.py
touch app/models/__init__.py
touch app/ingestors/__init__.py
touch app/api/__init__.py
touch app/cli/__init__.py
touch app/utils/__init__.py
touch app/web/__init__.py

# Initialize database
echo "💾 Initializing database..."
python -c "
import sys
sys.path.insert(0, '.')
from app.models.database import init_db
init_db()
print('Database initialized successfully')
"

# Download sample logs for testing
echo "📊 Downloading sample logs..."
if command -v curl &> /dev/null; then
    curl -s -o logs/samples/nginx_access.log \
        https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/nginx_logs/nginx_logs || \
    echo "Warning: Failed to download sample logs, creating dummy logs instead"
else
    echo "curl not found, creating dummy logs"
fi

# Create dummy logs if download failed
if [ ! -f logs/samples/nginx_access.log ]; then
    echo "127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"\n127.0.0.1 - - [01/Jan/2024:00:00:01 +0000] \"POST /api/login HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n127.0.0.1 - - [01/Jan/2024:00:00:02 +0000] \"GET /admin.php HTTP/1.1\" 404 256 \"-\" \"sqlmap/1.0\"\n" > logs/samples/nginx_access.log
fi

# Create config.yaml if not exists
if [ ! -f config.yaml ]; then
    echo "⚙️ Creating default configuration..."
    cat > config.yaml << 'EOF'
app:
  name: "Unified Log Forensics Platform"
  version: "1.0.0"
  debug: true
  secret_key: "dev-secret-key-change-in-production"
  
storage:
  mode: "sqlite"
  sqlite_path: "./data/forensics.db"
  elasticsearch:
    hosts: ["localhost:9200"]
    index_prefix: "logs_"
  retention_days: 90
  
processing:
  batch_size: 1000
  max_workers: 4
  realtime_buffer: 10000
  correlation_window_seconds: 5
  
detection:
  endpoint_abuse:
    threshold_requests_per_minute: 100
    threshold_data_mb: 100
    sequential_hits: 10
  sql_injection:
    keywords:
      - "union"
      - "select"
      - "insert"
      - "update"
      - "delete"
      - "drop"
      - "sleep"
      - "benchmark"
      - "waitfor"
    suspicious_patterns:
      - "' or '1'='1"
      - "'--"
      - "/*"
      - "*/"
      - "exec("
      - "eval("
  ip_abuse:
    threshold_requests_per_second: 10
    unique_endpoints_threshold: 50
    burst_window_seconds: 60
    
web:
  host: "0.0.0.0"
  port: 8000
  debug: true
  auth_required: false
  cors_origins:
    - "http://localhost:3000"
    
logging:
  level: "INFO"
  file: "./logs/platform.log"
  max_size_mb: 100
  backup_count: 5
  
reports:
  output_dir: "./reports"
  formats: ["json", "csv", "pdf"]
  sensitive_data_redaction: true
  redaction_patterns:
    - "\d{3}-\d{2}-\d{4}"
    - "\d{16}"
    - "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"
EOF
fi

# Create a simple test script
echo "🧪 Creating test script..."
cat > test_analysis.py << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')

from app.core.parser import LogParser
from pathlib import Path

print("Testing log parser...")
parser = LogParser()
test_file = Path("logs/samples/nginx_access.log")

if test_file.exists():
    entries = list(parser.parse_file(test_file, "nginx", "access"))
    print(f"✓ Successfully parsed {len(entries)} log entries")
    if entries:
        print(f"  First entry: {entries[0].endpoint}")
else:
    print("✗ Test log file not found")
EOF

# Set permissions
echo "🔐 Setting permissions..."
chmod +x scripts/*.sh
chmod +x test_analysis.py

echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Test the installation: python test_analysis.py"
echo "2. Run analysis: python -m app.main analyze logs/samples/nginx_access.log"
echo "3. Start web interface: python -m app.main web"
echo ""
echo "📚 For Docker deployment: docker-compose up -d"
