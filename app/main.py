import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional
import click

from app.core.parser import LogParser
from app.core.analyzer import LogAnalyzer
from app.core.correlator import LogCorrelator
from app.core.detector import AnomalyDetector
from app.utils.reporters import ReportGenerator
from app.api.web import create_web_app
from app.cli.commands import cli

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensics_platform.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class UnifiedLogForensicsPlatform:
    """Main application class"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.parser = LogParser()
        self.analyzer = LogAnalyzer()
        self.correlator = LogCorrelator()
        self.detector = AnomalyDetector()
        self.reporter = ReportGenerator()
        
    def _load_config(self, config_path: Optional[str]) -> dict:
        """Load configuration from file"""
        import yaml
        default_config = {
            'app': {'name': 'Unified Log Forensics Platform'},
            'storage': {'mode': 'sqlite'},
            'processing': {'batch_size': 1000}
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        
        return default_config
    
    async def analyze_logs(self, log_paths: List[Path], 
                          time_range: Optional[tuple] = None):
        """Main analysis workflow"""
        try:
            # Parse logs
            all_entries = []
            for log_path in log_paths:
                logger.info(f"Parsing: {log_path}")
                
                # Auto-detect source
                source, log_type = self.parser.detect_log_source(log_path)
                if not source:
                    logger.warning(f"Could not detect source for: {log_path}")
                    continue
                
                # Parse entries
                entries = list(self.parser.parse_file(log_path, source, log_type))
                all_entries.extend(entries)
                logger.info(f"Parsed {len(entries)} entries from {log_path}")
            
            if not all_entries:
                logger.error("No log entries found")
                return
            
            # Filter by time range if specified
            if time_range:
                start_time, end_time = time_range
                filtered_entries = [
                    e for e in all_entries 
                    if start_time <= e.timestamp <= end_time
                ]
                logger.info(f"Filtered to {len(filtered_entries)} entries in time range")
            else:
                filtered_entries = all_entries
            
            # Run analyses
            logger.info("Running endpoint frequency analysis...")
            endpoint_analysis = self.analyzer.analyze_endpoint_frequency(filtered_entries)
            
            logger.info("Running IP behavior analysis...")
            ip_analysis = self.analyzer.analyze_ip_behavior(filtered_entries)
            
            logger.info("Detecting data exfiltration...")
            data_exfil = self.analyzer.detect_data_exfiltration(filtered_entries)
            
            logger.info("Detecting SQL injection attempts...")
            sql_injection = self.analyzer.detect_sql_injection(filtered_entries)
            
            logger.info("Detecting scanner activity...")
            scanner_activity = self.analyzer.detect_scanner_activity(filtered_entries)
            
            # Correlate findings
            logger.info("Correlating findings across log sources...")
            correlated_findings = self.correlator.correlate_activities(
                filtered_entries,
                endpoint_analysis,
                ip_analysis,
                data_exfil,
                sql_injection,
                scanner_activity
            )
            
            # Generate report
            logger.info("Generating report...")
            report = self.reporter.generate_comprehensive_report(
                endpoint_analysis=endpoint_analysis,
                ip_analysis=ip_analysis,
                data_exfiltration=data_exfil,
                sql_injection=sql_injection,
                scanner_activity=scanner_activity,
                correlated_findings=correlated_findings
            )
            
            # Save report
            output_dir = Path(self.config.get('reports', {}).get('output_dir', './reports'))
            output_dir.mkdir(exist_ok=True)
            
            # Save as JSON
            json_path = output_dir / 'forensics_report.json'
            self.reporter.save_json_report(report, json_path)
            logger.info(f"JSON report saved to: {json_path}")
            
            # Save as CSV
            csv_path = output_dir / 'forensics_report.csv'
            self.reporter.save_csv_report(report, csv_path)
            logger.info(f"CSV report saved to: {csv_path}")
            
            # Save as PDF
            pdf_path = output_dir / 'forensics_report.pdf'
            self.reporter.save_pdf_report(report, pdf_path)
            logger.info(f"PDF report saved to: {pdf_path}")
            
            # Print summary
            self._print_summary(report)
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
    
    def _print_summary(self, report: dict):
        """Print analysis summary to console"""
        print("\n" + "="*60)
        print("FORENSIC ANALYSIS SUMMARY")
        print("="*60)
        
        summary = report.get('summary', {})
        
        print(f"\n📊 Total Log Entries Analyzed: {summary.get('total_entries', 0):,}")
        print(f"⏱️  Time Range: {summary.get('time_range', 'N/A')}")
        
        print(f"\n🚨 CRITICAL FINDINGS:")
        print(f"   • High-risk Endpoints: {summary.get('critical_endpoints', 0)}")
        print(f"   • Malicious IPs: {summary.get('malicious_ips', 0)}")
        print(f"   • Data Exfiltration Attempts: {summary.get('data_exfiltration', 0)}")
        print(f"   • SQL Injection Attempts: {summary.get('sql_injection', 0)}")
        print(f"   • Scanner Activities: {summary.get('scanner_activity', 0)}")
        
        print(f"\n🔍 TOP FINDINGS:")
        
        # Top risky endpoints
        endpoints = report.get('endpoint_analysis', [])[:3]
        if endpoints:
            print(f"\n   Top Risky Endpoints:")
            for ep in endpoints:
                print(f"     • {ep.get('endpoint')} - Risk: {ep.get('risk_level')} "
                      f"({ep.get('total_hits'):,} hits)")
        
        # Top malicious IPs
        ips = report.get('ip_analysis', [])[:3]
        if ips:
            print(f"\n   Top Malicious IPs:")
            for ip in ips:
                print(f"     • {ip.get('ip_address')} - Risk: {ip.get('risk_level')} "
                      f"({ip.get('total_requests'):,} requests)")
        
        print(f"\n📁 Reports saved in: ./reports/")
        print("="*60)

async def realtime_monitoring(log_dir: Path):
    """Start real-time log monitoring"""
    from app.ingestors.streaming import LogStreamMonitor
    
    monitor = LogStreamMonitor(log_dir)
    await monitor.start_monitoring()

@click.group()
def main():
    """Unified Server Log Forensics Platform"""
    pass

@main.command()
@click.argument('log_paths', nargs=-1, type=click.Path(exists=True))
@click.option('--start-time', '-s', help='Start time (YYYY-MM-DD HH:MM:SS)')
@click.option('--end-time', '-e', help='End time (YYYY-MM-DD HH:MM:SS)')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file')
def analyze(log_paths, start_time, end_time, config):
    """Analyze log files"""
    from datetime import datetime
    
    # Parse time range
    time_range = None
    if start_time and end_time:
        try:
            start = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
            end = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
            time_range = (start, end)
        except ValueError:
            click.echo("Invalid time format. Use YYYY-MM-DD HH:MM:SS")
            return
    
    # Convert to Path objects
    paths = [Path(p) for p in log_paths]
    
    # Run analysis
    platform = UnifiedLogForensicsPlatform(config)
    asyncio.run(platform.analyze_logs(paths, time_range))

@main.command()
@click.argument('log_dir', type=click.Path(exists=True))
def monitor(log_dir):
    """Monitor logs in real-time"""
    asyncio.run(realtime_monitoring(Path(log_dir)))

@main.command()
@click.option('--host', default='0.0.0.0', help='Web interface host')
@click.option('--port', default=8000, help='Web interface port')
def web(host, port):
    """Start web dashboard"""
    import uvicorn
    
    app = create_web_app()
    uvicorn.run(app, host=host, port=port)

if __name__ == '__main__':
    main()
