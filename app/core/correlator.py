from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

class LogCorrelator:
    """Cross-layer log correlation engine"""
    
    def __init__(self, time_window: int = 5):
        self.time_window = time_window  # seconds
    
    def correlate_activities(self, entries: List[Any], *analyses) -> List[Dict]:
        """Correlate activities across different analyses"""
        correlations = []
        
        # This is a simplified correlation logic
        # In production, this would be much more sophisticated
        
        # Group entries by time window
        time_groups = defaultdict(list)
        for entry in entries:
            time_key = entry.timestamp.replace(second=0, microsecond=0)
            time_groups[time_key].append(entry)
        
        # Look for suspicious patterns across time windows
        for time_key, group_entries in time_groups.items():
            if len(group_entries) > 10:  # High activity in time window
                # Analyze the group
                suspicious_ips = set()
                suspicious_endpoints = set()
                
                for entry in group_entries:
                    # Check for suspicious characteristics
                    if self._is_suspicious_entry(entry):
                        if entry.remote_addr:
                            suspicious_ips.add(entry.remote_addr)
                        if entry.endpoint:
                            suspicious_endpoints.add(entry.endpoint)
                
                if suspicious_ips or suspicious_endpoints:
                    correlations.append({
                        "timestamp": time_key,
                        "suspicious_ips": list(suspicious_ips),
                        "suspicious_endpoints": list(suspicious_endpoints),
                        "total_requests": len(group_entries),
                        "unique_ips": len(set(e.remote_addr for e in group_entries if e.remote_addr)),
                        "sample_entries": [{
                            "endpoint": e.endpoint,
                            "ip": e.remote_addr,
                            "status": e.status_code,
                            "size": e.body_bytes_sent
                        } for e in group_entries[:3]]
                    })
        
        return correlations
    
    def _is_suspicious_entry(self, entry) -> bool:
        """Check if an entry is suspicious"""
        suspicious = False
        
        # Check for error status codes
        if entry.status_code and entry.status_code >= 400:
            suspicious = True
        
        # Check for large response sizes
        if entry.body_bytes_sent > 1024 * 1024:  # > 1MB
            suspicious = True
        
        # Check for suspicious endpoints
        if entry.endpoint:
            suspicious_paths = ["/admin", "/phpmyadmin", "/wp-admin", "/config", "/backup"]
            for path in suspicious_paths:
                if path in entry.endpoint.lower():
                    suspicious = True
                    break
        
        return suspicious
