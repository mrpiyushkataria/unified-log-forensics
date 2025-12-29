from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

Base = declarative_base()

class LogEntryDB(Base):
    """Database model for log entries"""
    __tablename__ = 'log_entries'
    
    id = Column(Integer, primary_key=True)
    source = Column(String(50))
    log_type = Column(String(50))
    raw = Column(Text)
    timestamp = Column(DateTime)
    remote_addr = Column(String(45))
    http_method = Column(String(10))
    endpoint = Column(String(500))
    query_params = Column(JSON)
    status_code = Column(Integer)
    body_bytes_sent = Column(Integer)
    user_agent = Column(String(500))
    referer = Column(String(500))
    message = Column(Text)
    additional_data = Column(JSON)
    file_path = Column(String(500))
    line_number = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<LogEntryDB(source={self.source}, endpoint={self.endpoint})>"

class AnalysisResult(Base):
    """Database model for analysis results"""
    __tablename__ = 'analysis_results'
    
    id = Column(Integer, primary_key=True)
    analysis_type = Column(String(100))
    result_data = Column(JSON)
    risk_score = Column(Float)
    risk_level = Column(String(20))
    timestamp = Column(DateTime, default=datetime.utcnow)
    parameters = Column(JSON)
    
    def __repr__(self):
        return f"<AnalysisResult(type={self.analysis_type}, score={self.risk_score})>"

class DetectionAlert(Base):
    """Database model for detection alerts"""
    __tablename__ = 'detection_alerts'
    
    id = Column(Integer, primary_key=True)
    alert_type = Column(String(100))
    severity = Column(String(20))
    description = Column(Text)
    evidence = Column(JSON)
    ip_address = Column(String(45))
    endpoint = Column(String(500))
    timestamp = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved = Column(Integer, default=0)
    resolved_at = Column(DateTime)
    
    def __repr__(self):
        return f"<DetectionAlert(type={self.alert_type}, severity={self.severity})>"

def init_db(db_path: str = "data/forensics.db"):
    """Initialize database"""
    try:
        # Create data directory if it doesn't exist
        import os
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Create engine and tables
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)
        
        logger.info(f"Database initialized at {db_path}")
        return engine
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

def get_session(db_path: str = "data/forensics.db"):
    """Get database session"""
    engine = create_engine(f"sqlite:///{db_path}")
    Session = sessionmaker(bind=engine)
    return Session()
