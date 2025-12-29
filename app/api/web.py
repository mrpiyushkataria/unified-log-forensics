from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Optional
import json
from pathlib import Path
import asyncio

from app.models.schemas import LogEntry, AnalysisRequest, ReportRequest
from app.main import UnifiedLogForensicsPlatform

app = FastAPI(
    title="Unified Log Forensics Platform API",
    description="Real-time log analysis and forensic investigation platform",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global platform instance
platform = UnifiedLogForensicsPlatform()

@app.get("/")
async def root():
    """Root endpoint with API documentation"""
    return {
        "message": "Unified Log Forensics Platform API",
        "version": "1.0.0",
        "endpoints": {
            "/api/analyze": "Analyze uploaded logs",
            "/api/realtime/start": "Start real-time monitoring",
            "/api/reports": "Get analysis reports",
            "/dashboard": "Web dashboard"
        }
    }

@app.post("/api/analyze")
async def analyze_logs(
    files: List[UploadFile] = File(...),
    background_tasks: BackgroundTasks = None
):
    """Upload and analyze log files"""
    try:
        # Save uploaded files temporarily
        temp_dir = Path("/tmp/log_forensics")
        temp_dir.mkdir(exist_ok=True)
        
        saved_paths = []
        for file in files:
            file_path = temp_dir / file.filename
            with open(file_path, "wb") as f:
                content = await file.read()
                f.write(content)
            saved_paths.append(file_path)
        
        # Run analysis in background
        task_id = f"analysis_{len(saved_paths)}_{asyncio.get_event_loop().time()}"
        
        background_tasks.add_task(
            _run_analysis_async,
            saved_paths,
            task_id
        )
        
        return {
            "task_id": task_id,
            "message": "Analysis started",
            "files": [str(p) for p in saved_paths],
            "status": "processing"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze/advanced")
async def advanced_analysis(request: AnalysisRequest):
    """Advanced analysis with custom parameters"""
    try:
        # Parse time range
        time_range = None
        if request.start_time and request.end_time:
            time_range = (request.start_time, request.end_time)
        
        # Run analysis
        paths = [Path(p) for p in request.log_paths]
        
        await platform.analyze_logs(
            log_paths=paths,
            time_range=time_range
        )
        
        # Get latest report
        reports_dir = Path("./reports")
        latest_report = max(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        
        with open(latest_report, 'r') as f:
            report_data = json.load(f)
        
        return JSONResponse(content=report_data)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/realtime/start")
async def start_realtime_monitoring(log_dir: str):
    """Start real-time log monitoring"""
    try:
        asyncio.create_task(
            platform.realtime_monitoring(Path(log_dir))
        )
        return {"status": "started", "log_dir": log_dir}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/realtime/status")
async def get_realtime_status():
    """Get real-time monitoring status"""
    return {
        "status": "active",
        "monitored_dirs": ["/var/log/nginx", "/var/log/apache2"],
        "processed_files": 42,
        "alerts_generated": 5
    }

@app.get("/api/reports")
async def get_reports():
    """List available reports"""
    reports_dir = Path("./reports")
    if not reports_dir.exists():
        return []
    
    reports = []
    for report_file in reports_dir.glob("*.json"):
        stat = report_file.stat()
        reports.append({
            "name": report_file.name,
            "path": str(report_file),
            "size": stat.st_size,
            "created": stat.st_ctime,
            "modified": stat.st_mtime
        })
    
    return sorted(reports, key=lambda x: x["modified"], reverse=True)

@app.get("/api/reports/{report_name}")
async def get_report(report_name: str, format: str = "json"):
    """Get specific report in requested format"""
    reports_dir = Path("./reports")
    report_path = reports_dir / report_name
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    if format == "json":
        with open(report_path, 'r') as f:
            return JSONResponse(content=json.load(f))
    elif format == "csv":
        csv_path = report_path.with_suffix('.csv')
        if csv_path.exists():
            return FileResponse(csv_path, filename=csv_path.name)
    elif format == "pdf":
        pdf_path = report_path.with_suffix('.pdf')
        if pdf_path.exists():
            return FileResponse(pdf_path, filename=pdf_path.name)
    
    raise HTTPException(status_code=400, detail="Format not available")

@app.get("/api/endpoints/top")
async def get_top_endpoints(limit: int = 10, risk_level: Optional[str] = None):
    """Get top endpoints by risk"""
    # This would typically query from database
    return {"endpoints": [], "limit": limit}

@app.get("/api/ips/top")
async def get_top_ips(limit: int = 10):
    """Get top IPs by risk score"""
    return {"ips": [], "limit": limit}

@app.get("/api/detections/sql")
async def get_sql_detections():
    """Get SQL injection detections"""
    return {"detections": []}

@app.get("/api/detections/scanners")
async def get_scanner_detections():
    """Get scanner activity detections"""
    return {"scanners": []}

@app.get("/api/correlations")
async def get_correlated_findings():
    """Get correlated findings across log sources"""
    return {"correlations": []}

@app.get("/dashboard")
async def dashboard():
    """Serve web dashboard"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Log Forensics Dashboard</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
            .dashboard { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
            .card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .card h3 { margin-top: 0; }
            .critical { color: #dc3545; }
            .high { color: #fd7e14; }
            .medium { color: #ffc107; }
            .low { color: #28a745; }
        </style>
    </head>
    <body>
        <h1>🔍 Unified Log Forensics Dashboard</h1>
        <div class="dashboard">
            <div class="card">
                <h3>📊 Overview</h3>
                <div id="overview"></div>
            </div>
            <div class="card">
                <h3>🚨 High-Risk Endpoints</h3>
                <div id="endpoints"></div>
            </div>
            <div class="card">
                <h3>🌐 Malicious IPs</h3>
                <div id="ips"></div>
            </div>
            <div class="card">
                <h3>📈 Activity Timeline</h3>
                <div id="timeline"></div>
            </div>
        </div>
        <script>
            // Fetch and display data
            async function loadDashboard() {
                const [overview, endpoints, ips] = await Promise.all([
                    fetch('/api/analyze/overview').then(r => r.json()),
                    fetch('/api/endpoints/top?limit=5').then(r => r.json()),
                    fetch('/api/ips/top?limit=5').then(r => r.json())
                ]);
                
                // Update UI with data
                updateOverview(overview);
                updateEndpoints(endpoints);
                updateIPs(ips);
            }
            
            function updateOverview(data) {
                document.getElementById('overview').innerHTML = `
                    <p>Total Logs: ${data.total_logs || 0}</p>
                    <p>Critical Findings: <span class="critical">${data.critical || 0}</span></p>
                    <p>High Risk: <span class="high">${data.high || 0}</span></p>
                    <p>Real-time Monitoring: ${data.realtime ? '✅ Active' : '❌ Inactive'}</p>
                `;
            }
            
            function updateEndpoints(data) {
                const endpoints = data.endpoints || [];
                let html = '<ul>';
                endpoints.forEach(ep => {
                    html += `<li><strong>${ep.endpoint}</strong> - ${ep.risk_level} (${ep.hits} hits)</li>`;
                });
                html += '</ul>';
                document.getElementById('endpoints').innerHTML = html;
            }
            
            function updateIPs(data) {
                const ips = data.ips || [];
                let html = '<ul>';
                ips.forEach(ip => {
                    html += `<li><strong>${ip.address}</strong> - ${ip.risk_level} (${ip.requests} requests)</li>`;
                });
                html += '</ul>';
                document.getElementById('ips').innerHTML = html;
            }
            
            // Load dashboard on page load
            document.addEventListener('DOMContentLoaded', loadDashboard);
            
            // Auto-refresh every 30 seconds
            setInterval(loadDashboard, 30000);
        </script>
    </body>
    </html>
    """)

async def _run_analysis_async(log_paths: List[Path], task_id: str):
    """Background task for running analysis"""
    try:
        await platform.analyze_logs(log_paths)
        # Update task status in database/redis
        print(f"Analysis {task_id} completed successfully")
    except Exception as e:
        print(f"Analysis {task_id} failed: {e}")

def create_web_app() -> FastAPI:
    """Create and configure FastAPI application"""
    return app
