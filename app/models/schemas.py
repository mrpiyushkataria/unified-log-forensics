from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class LogSource(str, Enum):
    NGINX = "nginx"
    APACHE = "apache"
    MYSQL = "mysql"
    PHP = "php"
    GENERIC = "generic"

class LogType(str, Enum):
    ACCESS = "access"
    ERROR = "error"
    GENERAL = "general"
    SLOW = "slow"
    FPM = "fpm"
    APPLICATION = "application"

class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"
    UNKNOWN = "UNKNOWN"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LogEntry(BaseModel):
    """Schema for parsed log entry"""
    source: LogSource
    log_type: LogType
    raw: str
    timestamp: datetime
    remote_addr: Optional[str] = None
    http_method: Optional[HTTPMethod] = None
    endpoint: Optional[str] = None
    query_params: Optional[Dict[str, Any]] = None
    status_code: Optional[int] = None
    body_bytes_sent: int = 0
    user_agent: Optional[str] = None
    referer: Optional[str] = None
    message: Optional[str] = None
    additional_data: Dict[str, Any] = Field(default_factory=dict)
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    class Config:
        arbitrary_types_allowed = True

class DetectionRule(BaseModel):
    """Schema for detection rule"""
    name: str
    description: str
    condition: str  # This would be a serializable condition
    risk_level: RiskLevel
    enabled: bool = True

class AnalysisRequest(BaseModel):
    """Schema for analysis request"""
    log_paths: List[str]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    analysis_types: List[str] = Field(default_factory=lambda: ["all"])
    output_format: str = "json"
    
class ReportRequest(BaseModel):
    """Schema for report generation request"""
    analysis_id: Optional[str] = None
    time_range: Optional[Dict[str, datetime]] = None
    filters: Optional[Dict[str, Any]] = None
    format: str = "pdf"
    include_details: bool = True
