import re
from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

from app.models.schemas import LogEntry, RiskLevel

class AnomalyDetector:
    """Anomaly detection engine"""
    
    def __init__(self):
        self.sql_patterns = [
            r"(union.*select)",
            r"(select.*from)",
            r"(insert.*into)",
            r"(update.*set)",
            r"(delete.*from)",
            r"(drop.*table)",
            r"(sleep\s*\(\d+\))",
            r"(benchmark\s*\(.*\))",
            r"(waitfor\s*delay)",
            r"('or'.*'=')",
            r"(--)",
            r"(/\*.*\*/)",
            r"(;\s*--)"
        ]
        
        self.xss_patterns = [
            r"(<script.*>)",
            r"(javascript:)",
            r"(onerror\s*=)",
            r"(onload\s*=)",
            r"(alert\s*\()"
        ]
        
        self.lfi_patterns = [
            r"(\.\./)",
            r"(\.\.\\)",
            r"(/etc/passwd)",
            r"(c:\\windows\\)",
            r"(php://)",
            r"(data://)"
        ]
        
        self.scanner_user_agents = [
            "sqlmap", "nmap", "nikto", "dirb", "dirbuster", "wpscan",
            "acunetix", "nessus", "openvas", "burpsuite", "metasploit"
        ]
    
    def detect_anomalies(self, entries: List[LogEntry]) -> Dict[str, List[Dict]]:
        """Detect various anomalies in log entries"""
        anomalies = {
            "sql_injection": [],
            "xss": [],
            "lfi": [],
            "scanner": [],
            "brute_force": [],
            "data_dumping": []
        }
        
        # Group entries by IP for behavioral analysis
        ip_entries = defaultdict(list)
        for entry in entries:
            if entry.remote_addr:
                ip_entries[entry.remote_addr].append(entry)
        
        # Detect SQL injection
        anomalies["sql_injection"] = self._detect_sql_injection(entries)
        
        # Detect XSS attempts
        anomalies["xss"] = self._detect_xss(entries)
        
        # Detect LFI attempts
        anomalies["lfi"] = self._detect_lfi(entries)
        
        # Detect scanners
        anomalies["scanner"] = self._detect_scanners(entries)
        
        # Detect brute force attacks
        anomalies["brute_force"] = self._detect_brute_force(ip_entries)
        
        # Detect data dumping
        anomalies["data_dumping"] = self._detect_data_dumping(ip_entries)
        
        return anomalies
    
    def _detect_sql_injection(self, entries: List[LogEntry]) -> List[Dict]:
        """Detect SQL injection attempts"""
        findings = []
        
        for entry in entries:
            detected = False
            patterns_found = []
            
            # Check query parameters
            if entry.query_params:
                param_str = str(entry.query_params).lower()
                for pattern in self.sql_patterns:
                    if re.search(pattern, param_str, re.IGNORECASE):
                        detected = True
                        patterns_found.append(pattern)
            
            # Check endpoint
            if entry.endpoint:
                endpoint_lower = entry.endpoint.lower()
                for pattern in self.sql_patterns:
                    if re.search(pattern, endpoint_lower, re.IGNORECASE):
                        detected = True
                        patterns_found.append(pattern)
            
            # Check message
            if entry.message:
                message_lower = entry.message.lower()
                for pattern in self.sql_patterns:
                    if re.search(pattern, message_lower, re.IGNORECASE):
                        detected = True
                        patterns_found.append(pattern)
            
            if detected:
                findings.append({
                    "timestamp": entry.timestamp,
                    "ip": entry.remote_addr,
                    "endpoint": entry.endpoint,
                    "patterns": list(set(patterns_found)),
                    "user_agent": entry.user_agent,
                    "raw": entry.raw[:200]
                })
        
        return findings
    
    def _detect_xss(self, entries: List[LogEntry]) -> List[Dict]:
        """Detect XSS attempts"""
        findings = []
        
        for entry in entries:
            detected = False
            patterns_found = []
            
            # Check query parameters
            if entry.query_params:
                param_str = str(entry.query_params)
                for pattern in self.xss_patterns:
                    if re.search(pattern, param_str, re.IGNORECASE):
                        detected = True
                        patterns_found.append(pattern)
            
            if detected:
                findings.append({
                    "timestamp": entry.timestamp,
                    "ip": entry.remote_addr,
                    "endpoint": entry.endpoint,
                    "patterns": patterns_found,
                    "user_agent": entry.user_agent
                })
        
        return findings
    
    def _detect_lfi(self, entries: List[LogEntry]) -> List[Dict]:
        """Detect Local File Inclusion attempts"""
        findings = []
        
        for entry in entries:
            detected = False
            patterns_found = []
            
            # Check query parameters
            if entry.query_params:
                param_str = str(entry.query_params)
                for pattern in self.lfi_patterns:
                    if re.search(pattern, param_str, re.IGNORECASE):
                        detected = True
                        patterns_found.append(pattern)
            
            # Check endpoint
            if entry.endpoint:
                for pattern in self.lfi_patterns:
                    if re.search(pattern, entry.endpoint, re.IGNORECASE):
                        detected = True
                        patterns_found.append(pattern)
            
            if detected:
                findings.append({
                    "timestamp": entry.timestamp,
                    "ip": entry.remote_addr,
                    "endpoint": entry.endpoint,
                    "patterns": patterns_found,
                    "user_agent": entry.user_agent
                })
        
        return findings
    
    def _detect_scanners(self, entries: List[LogEntry]) -> List[Dict]:
        """Detect scanning tools"""
        findings = []
        
        for entry in entries:
            if entry.user_agent:
                ua_lower = entry.user_agent.lower()
                for scanner in self.scanner_user_agents:
                    if scanner in ua_lower:
                        findings.append({
                            "timestamp": entry.timestamp,
                            "ip": entry.remote_addr,
                            "endpoint": entry.endpoint,
                            "scanner": scanner,
                            "user_agent": entry.user_agent,
                            "status_code": entry.status_code
                        })
                        break
        
        return findings
    
    def _detect_brute_force(self, ip_entries: Dict[str, List[LogEntry]]) -> List[Dict]:
        """Detect brute force attacks"""
        findings = []
        
        for ip, entries in ip_entries.items():
            if len(entries) < 10:  # Need minimum entries
                continue
            
            # Check for rapid failed login attempts
            failed_auth = [e for e in entries 
                          if e.status_code in [401, 403] 
                          or (e.endpoint and 'login' in e.endpoint.lower() and e.status_code != 200)]
            
            if len(failed_auth) >= 5:
                # Check time window (5 failures in 60 seconds)
                timestamps = [e.timestamp for e in failed_auth]
                timestamps.sort()
                
                if len(timestamps) >= 5:
                    time_diff = (timestamps[-1] - timestamps[0]).total_seconds()
                    if time_diff <= 60:
                        findings.append({
                            "ip": ip,
                            "attempts": len(failed_auth),
                            "time_window": time_diff,
                            "first_attempt": timestamps[0],
                            "last_attempt": timestamps[-1],
                            "endpoints": list(set(e.endpoint for e in failed_auth if e.endpoint))
                        })
        
        return findings
    
    def _detect_data_dumping(self, ip_entries: Dict[str, List[LogEntry]]) -> List[Dict]:
        """Detect data dumping patterns"""
        findings = []
        
        for ip, entries in ip_entries.items():
            if len(entries) < 20:
                continue
            
            # Sort by timestamp
            entries.sort(key=lambda x: x.timestamp)
            
            # Look for sequential numeric patterns
            numeric_endpoints = []
            for entry in entries:
                if entry.endpoint:
                    import re
                    match = re.search(r'/(\d+)(?:/|$)', entry.endpoint)
                    if match:
                        numeric_endpoints.append(int(match.group(1)))
            
            # Check for sequential IDs
            if len(numeric_endpoints) >= 10:
                unique_ids = sorted(set(numeric_endpoints))
                if len(unique_ids) >= 10:
                    # Check if IDs are mostly sequential
                    sequential_count = 0
                    for i in range(len(unique_ids) - 1):
                        if unique_ids[i + 1] - unique_ids[i] == 1:
                            sequential_count += 1
                    
                    if sequential_count >= 8:  # At least 80% sequential
                        findings.append({
                            "ip": ip,
                            "total_requests": len(entries),
                            "sequential_ids": len(numeric_endpoints),
                            "id_range": f"{min(numeric_endpoints)}-{max(numeric_endpoints)}",
                            "time_range": (entries[-1].timestamp - entries[0].timestamp).total_seconds()
                        })
        
        return findings
