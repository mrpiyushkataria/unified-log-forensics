import re
import json
import gzip
import bz2
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Generator, Union
from dataclasses import dataclass
import logging
from urllib.parse import urlparse, parse_qs

from app.models.schemas import LogEntry, LogSource, HTTPMethod, LogType

logger = logging.getLogger(__name__)

class LogParser:
    """Unified log parser supporting multiple log formats"""
    
    # Common log patterns
    NGINX_COMBINED = r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
    APACHE_COMBINED = r'(?P<host>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
    MYSQL_GENERAL = r'(?P<time>\d{6} \d{2}:\d{2}:\d{2})\s+(?P<id>\d+)\s+(?P<command>\w+)\s+(?P<query>.*)'
    PHP_ERROR = r'\[(?P<timestamp>[^\]]+)\] (?P<type>\w+): (?P<message>.*) in (?P<file>.*) on line (?P<line>\d+)'
    
    def __init__(self):
        self.patterns = {
            LogSource.NGINX: {
                'access': re.compile(self.NGINX_COMBINED),
                'error': re.compile(r'(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+).(?P<tid>\d+): (?P<message>.*)')
            },
            LogSource.APACHE: {
                'access': re.compile(self.APACHE_COMBINED),
                'error': re.compile(r'\[(?P<timestamp>[^\]]+)\] \[(?P<module>\w+):(?P<level>\w+)\] \[pid (?P<pid>\d+):tid (?P<tid>\d+)\] (?P<message>.*)')
            },
            LogSource.MYSQL: {
                'general': re.compile(self.MYSQL_GENERAL),
                'slow': re.compile(r'Query_time: (?P<query_time>\d+\.\d+)\s+Lock_time: (?P<lock_time>\d+\.\d+).*?\n(?P<query>.*?)\n')
            },
            LogSource.PHP: {
                'error': re.compile(self.PHP_ERROR),
                'fpm': re.compile(r'\[(?P<date>\d{2}-[a-zA-Z]{3}-\d{4}:\d{2}:\d{2}:\d{2}) (?P<timezone>[^\]]+)\] (?P<level>\w+): (?P<message>.*)')
            }
        }
    
    def parse_line(self, line: str, source: LogSource, log_type: LogType) -> Optional[LogEntry]:
        """Parse a single log line"""
        try:
            if source not in self.patterns or log_type.value not in self.patterns[source]:
                return self._parse_generic(line, source, log_type)
            
            pattern = self.patterns[source][log_type.value]
            match = pattern.match(line.strip())
            
            if not match:
                return None
            
            data = match.groupdict()
            
            # Extract HTTP method and endpoint from request
            http_method = HTTPMethod.UNKNOWN
            endpoint = ""
            query_params = {}
            
            if 'request' in data:
                request_parts = data['request'].split()
                if len(request_parts) >= 2:
                    method_str = request_parts[0]
                    url = request_parts[1]
                    http_method = self._parse_http_method(method_str)
                    endpoint, query_params = self._extract_endpoint_and_params(url)
            
            # Parse timestamp
            timestamp = self._parse_timestamp(data.get('time_local') or data.get('time') or data.get('timestamp'))
            
            # Create log entry
            return LogEntry(
                source=source,
                log_type=log_type,
                raw=line.strip(),
                timestamp=timestamp,
                remote_addr=data.get('remote_addr') or data.get('host'),
                http_method=http_method,
                endpoint=endpoint,
                query_params=query_params,
                status_code=int(data.get('status', 0)) if data.get('status') else None,
                body_bytes_sent=int(data.get('body_bytes_sent') or data.get('size') or 0),
                user_agent=data.get('http_user_agent') or data.get('agent'),
                referer=data.get('http_referer') or data.get('referer'),
                message=data.get('message') or data.get('query') or '',
                additional_data={k: v for k, v in data.items() if k not in [
                    'remote_addr', 'host', 'time_local', 'time', 'timestamp',
                    'request', 'status', 'body_bytes_sent', 'size',
                    'http_user_agent', 'agent', 'http_referer', 'referer',
                    'message', 'query'
                ]}
            )
            
        except Exception as e:
            logger.error(f"Failed to parse line: {e}")
            return None
    
    def _parse_http_method(self, method: str) -> HTTPMethod:
        """Parse HTTP method from string"""
        method_upper = method.upper()
        for http_method in HTTPMethod:
            if http_method.value == method_upper:
                return http_method
        return HTTPMethod.UNKNOWN
    
    def _extract_endpoint_and_params(self, url: str) -> tuple[str, dict]:
        """Extract endpoint and query parameters from URL"""
        try:
            parsed = urlparse(url)
            endpoint = parsed.path
            query_params = parse_qs(parsed.query)
            return endpoint, query_params
        except:
            return url, {}
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp from various formats"""
        formats = [
            '%d/%b/%Y:%H:%M:%S %z',
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%b %d %H:%M:%S',
            '%Y%m%d %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Return current time if parsing fails
        return datetime.now()
    
    def _parse_generic(self, line: str, source: LogSource, log_type: LogType) -> Optional[LogEntry]:
        """Parse generic log format"""
        try:
            # Try to extract basic information
            parts = line.split()
            if len(parts) >= 3:
                return LogEntry(
                    source=source,
                    log_type=log_type,
                    raw=line.strip(),
                    timestamp=datetime.now(),
                    message=line.strip()
                )
        except:
            pass
        return None
    
    def parse_file(self, file_path: Path, source: LogSource, log_type: LogType) -> Generator[LogEntry, None, None]:
        """Parse log file and yield entries"""
        open_func = open
        
        # Handle compressed files
        if file_path.suffix == '.gz':
            open_func = gzip.open
        elif file_path.suffix == '.bz2':
            open_func = bz2.open
        
        try:
            with open_func(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self.parse_line(line, source, log_type)
                    if entry:
                        entry.line_number = line_num
                        entry.file_path = str(file_path)
                        yield entry
        except Exception as e:
            logger.error(f"Failed to parse file {file_path}: {e}")
    
    def detect_log_source(self, file_path: Path) -> tuple[Optional[LogSource], Optional[LogType]]:
        """Auto-detect log source and type from file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample_lines = [next(f) for _ in range(10)]
                
            sample_text = ''.join(sample_lines)
            
            # Check for Nginx
            if 'nginx' in sample_text.lower() or 'GET /' in sample_text or 'POST /' in sample_text:
                if 'error.log' in str(file_path):
                    return LogSource.NGINX, LogType.ERROR
                return LogSource.NGINX, LogType.ACCESS
            
            # Check for Apache
            if 'apache' in sample_text.lower() or 'Apache' in sample_text:
                if 'error.log' in str(file_path):
                    return LogSource.APACHE, LogType.ERROR
                return LogSource.APACHE, LogType.ACCESS
            
            # Check for MySQL
            if 'Query' in sample_text and ('SELECT' in sample_text or 'INSERT' in sample_text):
                if 'slow' in str(file_path).lower():
                    return LogSource.MYSQL, LogType.SLOW
                return LogSource.MYSQL, LogType.GENERAL
            
            # Check for PHP
            if 'PHP' in sample_text or '.php' in sample_text.lower():
                if 'fpm' in str(file_path).lower():
                    return LogSource.PHP, LogType.FPM
                return LogSource.PHP, LogType.ERROR
            
        except Exception as e:
            logger.error(f"Failed to detect log source: {e}")
        
        return None, None
