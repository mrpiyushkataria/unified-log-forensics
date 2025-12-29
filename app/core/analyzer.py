import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
import logging
from enum import Enum

from app.models.schemas import LogEntry, DetectionRule, RiskLevel
from app.core.scoring import RiskScorer

logger = logging.getLogger(__name__)

class AnalysisType(Enum):
    ENDPOINT_FREQUENCY = "endpoint_frequency"
    IP_BEHAVIOR = "ip_behavior"
    DATA_EXFILTRATION = "data_exfiltration"
    SQL_INJECTION = "sql_injection"
    TEMPORAL_PATTERN = "temporal_pattern"

@dataclass
class EndpointAnalysis:
    endpoint: str
    total_hits: int
    unique_ips: int
    total_data_bytes: int
    time_distribution: Dict[str, int]
    http_methods: Dict[str, int]
    status_codes: Dict[int, int]
    first_seen: datetime
    last_seen: datetime
    average_response_size: float
    requests_per_minute: float
    risk_score: float
    risk_level: RiskLevel

@dataclass
class IPAnalysis:
    ip_address: str
    total_requests: int
    unique_endpoints: int
    total_data_bytes: int
    user_agents: List[str]
    request_patterns: List[str]
    first_seen: datetime
    last_seen: datetime
    requests_per_second: float
    endpoint_coverage: float
    suspicious_activities: List[str]
    risk_score: float
    risk_level: RiskLevel

class LogAnalyzer:
    """Core log analysis engine"""
    
    def __init__(self, risk_scorer: Optional[RiskScorer] = None):
        self.risk_scorer = risk_scorer or RiskScorer()
        self.detection_rules = self._load_detection_rules()
    
    def analyze_endpoint_frequency(self, entries: List[LogEntry], 
                                   top_n: int = 100) -> List[EndpointAnalysis]:
        """Analyze endpoint call frequency and behavior"""
        endpoint_data = defaultdict(lambda: {
            'hits': 0,
            'ips': set(),
            'data_bytes': 0,
            'timestamps': [],
            'methods': Counter(),
            'status_codes': Counter(),
            'first_seen': None,
            'last_seen': None
        })
        
        # Aggregate endpoint data
        for entry in entries:
            if not entry.endpoint:
                continue
                
            data = endpoint_data[entry.endpoint]
            data['hits'] += 1
            if entry.remote_addr:
                data['ips'].add(entry.remote_addr)
            data['data_bytes'] += entry.body_bytes_sent
            data['timestamps'].append(entry.timestamp)
            if entry.http_method:
                data['methods'][entry.http_method.value] += 1
            if entry.status_code:
                data['status_codes'][entry.status_code] += 1
            
            if not data['first_seen'] or entry.timestamp < data['first_seen']:
                data['first_seen'] = entry.timestamp
            if not data['last_seen'] or entry.timestamp > data['last_seen']:
                data['last_seen'] = entry.timestamp
        
        # Convert to analysis objects
        results = []
        for endpoint, data in endpoint_data.items():
            time_range = (data['last_seen'] - data['first_seen']).total_seconds()
            requests_per_minute = (data['hits'] / (time_range / 60)) if time_range > 0 else data['hits']
            
            # Calculate time distribution by hour
            time_dist = Counter()
            for ts in data['timestamps']:
                hour = ts.strftime('%Y-%m-%d %H:00')
                time_dist[hour] += 1
            
            analysis = EndpointAnalysis(
                endpoint=endpoint,
                total_hits=data['hits'],
                unique_ips=len(data['ips']),
                total_data_bytes=data['data_bytes'],
                time_distribution=dict(time_dist),
                http_methods=dict(data['methods']),
                status_codes=dict(data['status_codes']),
                first_seen=data['first_seen'],
                last_seen=data['last_seen'],
                average_response_size=data['data_bytes'] / data['hits'] if data['hits'] > 0 else 0,
                requests_per_minute=requests_per_minute,
                risk_score=0.0,
                risk_level=RiskLevel.LOW
            )
            
            # Calculate risk score
            risk_score = self.risk_scorer.calculate_endpoint_risk(analysis)
            analysis.risk_score = risk_score
            analysis.risk_level = self.risk_scorer.score_to_risk_level(risk_score)
            
            results.append(analysis)
        
        # Sort by risk score and hits
        results.sort(key=lambda x: (x.risk_score, x.total_hits), reverse=True)
        return results[:top_n]
    
    def analyze_ip_behavior(self, entries: List[LogEntry], 
                           top_n: int = 50) -> List[IPAnalysis]:
        """Analyze IP behavior and detect malicious activity"""
        ip_data = defaultdict(lambda: {
            'requests': 0,
            'endpoints': set(),
            'data_bytes': 0,
            'user_agents': set(),
            'timestamps': [],
            'first_seen': None,
            'last_seen': None,
            'activities': []
        })
        
        # Aggregate IP data
        for entry in entries:
            if not entry.remote_addr:
                continue
                
            data = ip_data[entry.remote_addr]
            data['requests'] += 1
            if entry.endpoint:
                data['endpoints'].add(entry.endpoint)
            data['data_bytes'] += entry.body_bytes_sent
            if entry.user_agent:
                data['user_agents'].add(entry.user_agent)
            data['timestamps'].append(entry.timestamp)
            
            if not data['first_seen'] or entry.timestamp < data['first_seen']:
                data['first_seen'] = entry.timestamp
            if not data['last_seen'] or entry.timestamp > data['last_seen']:
                data['last_seen'] = entry.timestamp
        
        # Convert to analysis objects
        results = []
        for ip, data in ip_data.items():
            time_range = (data['last_seen'] - data['first_seen']).total_seconds()
            requests_per_second = (data['requests'] / time_range) if time_range > 0 else data['requests']
            
            # Detect suspicious activities
            activities = []
            if requests_per_second > 10:  # More than 10 requests per second
                activities.append(f"High request rate: {requests_per_second:.2f} req/sec")
            
            if len(data['endpoints']) > 50:  # Accessed many endpoints
                activities.append(f"Wide endpoint coverage: {len(data['endpoints'])} endpoints")
            
            if len(data['user_agents']) > 5:  # Multiple user agents
                activities.append(f"Multiple user agents: {len(data['user_agents'])}")
            
            analysis = IPAnalysis(
                ip_address=ip,
                total_requests=data['requests'],
                unique_endpoints=len(data['endpoints']),
                total_data_bytes=data['data_bytes'],
                user_agents=list(data['user_agents']),
                request_patterns=self._extract_request_patterns(ip, entries),
                first_seen=data['first_seen'],
                last_seen=data['last_seen'],
                requests_per_second=requests_per_second,
                endpoint_coverage=len(data['endpoints']) / data['requests'] if data['requests'] > 0 else 0,
                suspicious_activities=activities,
                risk_score=0.0,
                risk_level=RiskLevel.LOW
            )
            
            # Calculate risk score
            risk_score = self.risk_scorer.calculate_ip_risk(analysis)
            analysis.risk_score = risk_score
            analysis.risk_level = self.risk_scorer.score_to_risk_level(risk_score)
            
            results.append(analysis)
        
        # Sort by risk score and requests
        results.sort(key=lambda x: (x.risk_score, x.total_requests), reverse=True)
        return results[:top_n]
    
    def detect_data_exfiltration(self, entries: List[LogEntry], 
                               threshold_mb: float = 100) -> List[Dict]:
        """Detect potential data exfiltration patterns"""
        suspicious_endpoints = []
        
        # Group by endpoint
        endpoint_groups = defaultdict(list)
        for entry in entries:
            if entry.endpoint and entry.body_bytes_sent > 0:
                endpoint_groups[entry.endpoint].append(entry)
        
        # Analyze each endpoint
        for endpoint, endpoint_entries in endpoint_groups.items():
            total_data = sum(e.body_bytes_sent for e in endpoint_entries)
            total_data_mb = total_data / (1024 * 1024)
            
            if total_data_mb > threshold_mb:
                # Check for sequential access patterns (data dumping)
                sequential_hits = self._detect_sequential_hits(endpoint_entries)
                
                # Check for rapid data transfer
                time_range = (max(e.timestamp for e in endpoint_entries) - 
                            min(e.timestamp for e in endpoint_entries)).total_seconds()
                data_rate_mbps = total_data_mb / (time_range / 60) if time_range > 0 else 0
                
                if sequential_hits > 10 or data_rate_mbps > 10:
                    suspicious_endpoints.append({
                        'endpoint': endpoint,
                        'total_data_mb': total_data_mb,
                        'total_requests': len(endpoint_entries),
                        'unique_ips': len(set(e.remote_addr for e in endpoint_entries if e.remote_addr)),
                        'sequential_hits': sequential_hits,
                        'data_rate_mbps': data_rate_mbps,
                        'time_range_seconds': time_range,
                        'sample_requests': [{
                            'timestamp': e.timestamp.isoformat(),
                            'ip': e.remote_addr,
                            'size_mb': e.body_bytes_sent / (1024 * 1024)
                        } for e in endpoint_entries[:5]]
                    })
        
        return suspicious_endpoints
    
    def detect_sql_injection(self, entries: List[LogEntry]) -> List[Dict]:
        """Detect SQL injection attempts"""
        sql_keywords = [
            'union', 'select', 'insert', 'update', 'delete', 'drop',
            'table', 'database', 'schema', 'or', 'and', 'xor',
            'sleep', 'benchmark', 'waitfor', 'delay', 'shutdown',
            'exec', 'execute', 'sp_', 'xp_', ';', '--', '/*', '*/',
            "' or '1'='1", "' or 1=1--", "' or 1=1#", "admin'--"
        ]
        
        suspicious_requests = []
        
        for entry in entries:
            # Check query parameters
            query_params = entry.query_params or {}
            found_keywords = []
            
            for param_value in query_params.values():
                if isinstance(param_value, list):
                    param_str = ' '.join(str(v) for v in param_value)
                else:
                    param_str = str(param_value)
                
                param_str_lower = param_str.lower()
                
                for keyword in sql_keywords:
                    if keyword in param_str_lower:
                        found_keywords.append(keyword)
            
            # Check message/raw log for SQL patterns
            if entry.message:
                message_lower = entry.message.lower()
                for keyword in sql_keywords:
                    if keyword in message_lower and keyword not in found_keywords:
                        found_keywords.append(keyword)
            
            if found_keywords:
                suspicious_requests.append({
                    'timestamp': entry.timestamp.isoformat(),
                    'ip': entry.remote_addr,
                    'endpoint': entry.endpoint,
                    'method': entry.http_method.value if entry.http_method else 'UNKNOWN',
                    'keywords_found': list(set(found_keywords)),
                    'query_params': query_params,
                    'user_agent': entry.user_agent,
                    'status_code': entry.status_code,
                    'raw_entry': entry.raw[:500]  # First 500 chars
                })
        
        return suspicious_requests
    
    def detect_scanner_activity(self, entries: List[LogEntry]) -> List[Dict]:
        """Detect web scanner and automated attack patterns"""
        scanner_patterns = {
            'sqlmap': ['sqlmap', '--level', '--risk', '--batch'],
            'nmap': ['nmap', '-sV', '-sC', '-O'],
            'nikto': ['nikto', '-h'],
            'dirb': ['dirb', 'dirbuster'],
            'wpscan': ['wpscan', '--enumerate'],
            'xss': ['<script>', 'alert(', 'onerror=', 'onload='],
            'lfi': ['../', '..\\', '/etc/passwd', 'C:\\windows\\'],
            'rfi': ['http://', 'https://', 'ftp://', 'php://'],
            'command_injection': [';', '|', '&', '`', '$(']
        }
        
        scanner_hits = defaultdict(lambda: {'count': 0, 'requests': []})
        
        for entry in entries:
            # Check user agent
            if entry.user_agent:
                ua_lower = entry.user_agent.lower()
                for scanner, patterns in scanner_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in ua_lower:
                            scanner_hits[scanner]['count'] += 1
                            scanner_hits[scanner]['requests'].append({
                                'timestamp': entry.timestamp.isoformat(),
                                'ip': entry.remote_addr,
                                'endpoint': entry.endpoint,
                                'user_agent': entry.user_agent
                            })
                            break
            
            # Check query parameters for scanner patterns
            query_params = entry.query_params or {}
            for param_value in query_params.values():
                if isinstance(param_value, list):
                    param_str = ' '.join(str(v) for v in param_value)
                else:
                    param_str = str(param_value)
                
                param_str_lower = param_str.lower()
                
                for scanner, patterns in scanner_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in param_str_lower:
                            scanner_hits[scanner]['count'] += 1
                            scanner_hits[scanner]['requests'].append({
                                'timestamp': entry.timestamp.isoformat(),
                                'ip': entry.remote_addr,
                                'endpoint': entry.endpoint,
                                'parameter_value': param_str[:200]
                            })
                            break
        
        # Convert to list and filter significant hits
        results = []
        for scanner, data in scanner_hits.items():
            if data['count'] >= 3:  # At least 3 hits to consider
                results.append({
                    'scanner_type': scanner,
                    'total_hits': data['count'],
                    'unique_ips': len(set(r['ip'] for r in data['requests'] if r.get('ip'))),
                    'sample_requests': data['requests'][:10]
                })
        
        return results
    
    def _extract_request_patterns(self, ip: str, entries: List[LogEntry]) -> List[str]:
        """Extract request patterns for an IP"""
        ip_entries = [e for e in entries if e.remote_addr == ip]
        
        if len(ip_entries) < 10:
            return []
        
        patterns = []
        
        # Check for sequential numeric IDs (data dumping)
        endpoints = [e.endpoint for e in ip_entries if e.endpoint]
        numeric_patterns = self._find_numeric_patterns(endpoints)
        if numeric_patterns:
            patterns.append(f"Sequential numeric patterns: {numeric_patterns}")
        
        # Check for timing patterns
        timestamps = [e.timestamp for e in ip_entries]
        time_pattern = self._analyze_timing_pattern(timestamps)
        if time_pattern:
            patterns.append(f"Timing pattern: {time_pattern}")
        
        return patterns
    
    def _find_numeric_patterns(self, endpoints: List[str]) -> str:
        """Find sequential numeric patterns in endpoints"""
        numeric_ids = []
        for endpoint in endpoints:
            # Look for numeric IDs in URLs
            import re
            numbers = re.findall(r'/(\d+)(?:/|$)', endpoint)
            if numbers:
                numeric_ids.extend([int(n) for n in numbers])
        
        if len(numeric_ids) >= 5:
            # Check if they're sequential
            sorted_ids = sorted(set(numeric_ids))
            if len(sorted_ids) >= 5:
                differences = [sorted_ids[i+1] - sorted_ids[i] for i in range(len(sorted_ids)-1)]
                if all(d == 1 for d in differences[:5]):
                    return f"Sequential IDs from {sorted_ids[0]} to {sorted_ids[4]}"
        
        return ""
    
    def _analyze_timing_pattern(self, timestamps: List[datetime]) -> str:
        """Analyze timing patterns between requests"""
        if len(timestamps) < 3:
            return ""
        
        timestamps.sort()
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                    for i in range(len(timestamps)-1)]
        
        # Check for consistent intervals (automated requests)
        interval_std = np.std(intervals) if len(intervals) > 1 else 0
        if interval_std < 0.1:  # Very consistent intervals
            avg_interval = np.mean(intervals)
            return f"Consistent interval: {avg_interval:.2f}s"
        
        # Check for burst patterns
        if any(i < 0.1 for i in intervals):  # Sub-100ms intervals
            burst_count = sum(1 for i in intervals if i < 0.1)
            return f"Burst pattern: {burst_count} rapid requests"
        
        return ""
    
    def _detect_sequential_hits(self, entries: List[LogEntry]) -> int:
        """Detect sequential hits from same IP"""
        if not entries:
            return 0
        
        entries.sort(key=lambda x: x.timestamp)
        
        max_seq = 1
        current_seq = 1
        
        for i in range(1, len(entries)):
            time_diff = (entries[i].timestamp - entries[i-1].timestamp).total_seconds()
            
            # Same IP and within 2 seconds
            if (entries[i].remote_addr == entries[i-1].remote_addr and 
                time_diff <= 2.0):
                current_seq += 1
                max_seq = max(max_seq, current_seq)
            else:
                current_seq = 1
        
        return max_seq
    
    def _load_detection_rules(self) -> List[DetectionRule]:
        """Load detection rules from configuration"""
        # This would typically load from config/database
        return [
            DetectionRule(
                name="high_frequency_endpoint",
                description="Endpoint with unusually high request frequency",
                condition=lambda x: x.requests_per_minute > 100,
                risk_level=RiskLevel.HIGH
            ),
            DetectionRule(
                name="data_exfiltration",
                description="Large data transfer from endpoint",
                condition=lambda x: x.total_data_bytes > 100 * 1024 * 1024,  # 100MB
                risk_level=RiskLevel.CRITICAL
            ),
            DetectionRule(
                name="multiple_404",
                description="Many 404 errors from same IP",
                condition=lambda x: x.status_codes.get(404, 0) > 50,
                risk_level=RiskLevel.MEDIUM
            )
        ]
