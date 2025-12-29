from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum
import numpy as np
from datetime import datetime

from app.models.schemas import RiskLevel

@dataclass
class RiskFactors:
    request_frequency: float = 0.0
    data_volume: float = 0.0
    endpoint_coverage: float = 0.0
    suspicious_patterns: float = 0.0
    sql_injection_indicators: float = 0.0
    scanner_indicators: float = 0.0
    error_rate: float = 0.0
    time_anomaly: float = 0.0

class RiskScorer:
    """Risk scoring engine for detected anomalies"""
    
    # Weight configuration for different factors
    WEIGHTS = {
        'request_frequency': 0.25,
        'data_volume': 0.20,
        'suspicious_patterns': 0.15,
        'sql_injection_indicators': 0.15,
        'scanner_indicators': 0.10,
        'endpoint_coverage': 0.08,
        'error_rate': 0.05,
        'time_anomaly': 0.02
    }
    
    # Thresholds for different risk levels
    THRESHOLDS = {
        RiskLevel.LOW: 0.3,
        RiskLevel.MEDIUM: 0.5,
        RiskLevel.HIGH: 0.7,
        RiskLevel.CRITICAL: 0.9
    }
    
    def calculate_endpoint_risk(self, endpoint_analysis) -> float:
        """Calculate risk score for an endpoint"""
        factors = RiskFactors()
        
        # Request frequency factor (0-1)
        if endpoint_analysis.requests_per_minute > 0:
            freq_score = min(endpoint_analysis.requests_per_minute / 1000, 1.0)
            factors.request_frequency = freq_score
        
        # Data volume factor
        data_gb = endpoint_analysis.total_data_bytes / (1024 ** 3)
        factors.data_volume = min(data_gb / 10, 1.0)  # Normalize to 10GB max
        
        # Suspicious patterns (404 errors, unusual methods)
        if 404 in endpoint_analysis.status_codes:
            error_ratio = endpoint_analysis.status_codes[404] / endpoint_analysis.total_hits
            factors.error_rate = min(error_ratio * 2, 1.0)
        
        # Method distribution anomaly
        if len(endpoint_analysis.http_methods) > 3:
            factors.suspicious_patterns = 0.3
        
        # Calculate weighted score
        score = sum(
            getattr(factors, factor) * weight 
            for factor, weight in self.WEIGHTS.items()
        )
        
        return min(score, 1.0)
    
    def calculate_ip_risk(self, ip_analysis) -> float:
        """Calculate risk score for an IP address"""
        factors = RiskFactors()
        
        # Request rate factor
        factors.request_frequency = min(ip_analysis.requests_per_second / 50, 1.0)
        
        # Endpoint coverage factor
        factors.endpoint_coverage = min(ip_analysis.unique_endpoints / 100, 1.0)
        
        # Suspicious activities factor
        factors.suspicious_patterns = min(len(ip_analysis.suspicious_activities) / 5, 1.0)
        
        # Multiple user agents factor
        if len(ip_analysis.user_agents) > 3:
            factors.scanner_indicators = min(len(ip_analysis.user_agents) / 10, 1.0)
        
        # Calculate weighted score
        score = sum(
            getattr(factors, factor) * weight 
            for factor, weight in self.WEIGHTS.items()
        )
        
        return min(score, 1.0)
    
    def calculate_sql_injection_risk(self, detection) -> float:
        """Calculate risk score for SQL injection detection"""
        factors = RiskFactors()
        
        # Number of SQL keywords found
        keyword_count = len(detection.get('keywords_found', []))
        factors.sql_injection_indicators = min(keyword_count / 5, 1.0)
        
        # Severity of keywords
        critical_keywords = ['union', 'select', 'sleep', 'benchmark', 'drop', 'shutdown']
        critical_count = sum(1 for kw in detection.get('keywords_found', []) 
                           if kw in critical_keywords)
        factors.sql_injection_indicators += min(critical_count / 3, 0.5)
        
        # Request success
        if detection.get('status_code') == 200:
            factors.sql_injection_indicators += 0.2
        
        return min(factors.sql_injection_indicators, 1.0)
    
    def score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level"""
        if score >= self.THRESHOLDS[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def generate_risk_breakdown(self, score: float, factors: RiskFactors) -> Dict:
        """Generate detailed risk breakdown"""
        breakdown = {}
        
        for factor in self.WEIGHTS.keys():
            factor_value = getattr(factors, factor, 0.0)
            factor_score = factor_value * self.WEIGHTS[factor]
            factor_percentage = (factor_score / score) * 100 if score > 0 else 0
            
            breakdown[factor] = {
                'value': factor_value,
                'weight': self.WEIGHTS[factor],
                'contribution': factor_score,
                'percentage': factor_percentage
            }
        
        return breakdown
