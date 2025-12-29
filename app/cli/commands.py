import click
import asyncio
from pathlib import Path
from datetime import datetime

@click.group()
def cli():
    """Unified Log Forensics Platform CLI"""
    pass

@cli.command()
@click.argument('log_paths', nargs=-1, type=click.Path(exists=True))
@click.option('--start-time', '-s', help='Start time (YYYY-MM-DD HH:MM:SS)')
@click.option('--end-time', '-e', help='End time (YYYY-MM-DD HH:MM:SS)')
@click.option('--output', '-o', type=click.Path(), default='./reports', 
              help='Output directory for reports')
def analyze(log_paths, start_time, end_time, output):
    """Analyze log files"""
    from app.main import UnifiedLogForensicsPlatform
    
    # Parse time range
    time_range = None
    if start_time and end_time:
        try:
            start = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
            end = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
            time_range = (start, end)
            click.echo(f"Time range: {start} to {end}")
        except ValueError:
            click.echo("Error: Invalid time format. Use YYYY-MM-DD HH:MM:SS")
            return
    
    # Convert to Path objects
    paths = [Path(p) for p in log_paths]
    
    if not paths:
        click.echo("Error: No log files specified")
        return
    
    click.echo(f"Analyzing {len(paths)} log files...")
    
    # Run analysis
    platform = UnifiedLogForensicsPlatform()
    
    # Create output directory
    output_path = Path(output)
    output_path.mkdir(exist_ok=True)
    
    asyncio.run(platform.analyze_logs(paths, time_range))
    
    click.echo(f"Analysis complete! Reports saved to {output_path}")

@cli.command()
@click.argument('log_dir', type=click.Path(exists=True))
@click.option('--interval', '-i', default=5, help='Check interval in seconds')
def monitor(log_dir, interval):
    """Monitor logs in real-time"""
    from app.ingestors.streaming import LogStreamMonitor
    
    click.echo(f"Starting real-time monitoring of {log_dir}...")
    click.echo(f"Check interval: {interval} seconds")
    click.echo("Press Ctrl+C to stop")
    
    try:
        monitor = LogStreamMonitor(Path(log_dir), interval)
        asyncio.run(monitor.start_monitoring())
    except KeyboardInterrupt:
        click.echo("\nMonitoring stopped")
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@click.option('--host', default='0.0.0.0', help='Web interface host')
@click.option('--port', default=8000, help='Web interface port')
@click.option('--reload', is_flag=True, help='Enable auto-reload')
def web(host, port, reload):
    """Start web dashboard"""
    import uvicorn
    
    click.echo(f"Starting web dashboard on {host}:{port}")
    
    uvicorn.run(
        "app.api.web:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )

@cli.command()
@click.argument('report_file', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['json', 'csv', 'html']), 
              default='json', help='Output format')
def view(report_file, format):
    """View analysis report"""
    import json
    from tabulate import tabulate
    
    report_path = Path(report_file)
    
    if not report_path.exists():
        click.echo(f"Error: Report file not found: {report_file}")
        return
    
    if format == 'json':
        with open(report_path, 'r') as f:
            data = json.load(f)
            click.echo(json.dumps(data, indent=2, default=str))
    elif format == 'csv':
        # Simple CSV viewer
        with open(report_path, 'r') as f:
            lines = f.readlines()
            for i, line in enumerate(lines[:20]):  # Show first 20 lines
                click.echo(line.strip())
            if len(lines) > 20:
                click.echo(f"... and {len(lines) - 20} more lines")
    elif format == 'html':
        click.echo(f"HTML view not implemented yet. Use --format json or csv")

@cli.command()
def initdb():
    """Initialize database"""
    from app.models.database import init_db
    
    try:
        init_db()
        click.echo("Database initialized successfully")
    except Exception as e:
        click.echo(f"Error initializing database: {e}")

if __name__ == '__main__':
    cli()
