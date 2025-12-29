import sqlite3
import json
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path

class LogStorage:
    """Storage management for log entries and analysis results"""
    
    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create log entries table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            log_type TEXT,
            raw TEXT,
            timestamp DATETIME,
            remote_addr TEXT,
            http_method TEXT,
            endpoint TEXT,
            query_params TEXT,
            status_code INTEGER,
            body_bytes_sent INTEGER,
            user_agent TEXT,
            referer TEXT,
            message TEXT,
            additional_data TEXT,
            file_path TEXT,
            line_number INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create analysis results table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_type TEXT,
            result_data TEXT,
            risk_score REAL,
            risk_level TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            parameters TEXT
        )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_ip ON log_entries(remote_addr)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_endpoint ON log_entries(endpoint)')
        
        conn.commit()
        conn.close()
    
    def save_log_entry(self, entry: Dict[str, Any]) -> int:
        """Save a log entry to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO log_entries 
        (source, log_type, raw, timestamp, remote_addr, http_method, endpoint, 
         query_params, status_code, body_bytes_sent, user_agent, referer, 
         message, additional_data, file_path, line_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get('source'),
            entry.get('log_type'),
            entry.get('raw'),
            entry.get('timestamp'),
            entry.get('remote_addr'),
            entry.get('http_method'),
            entry.get('endpoint'),
            json.dumps(entry.get('query_params')) if entry.get('query_params') else None,
            entry.get('status_code'),
            entry.get('body_bytes_sent'),
            entry.get('user_agent'),
            entry.get('referer'),
            entry.get('message'),
            json.dumps(entry.get('additional_data')) if entry.get('additional_data') else None,
            entry.get('file_path'),
            entry.get('line_number')
        ))
        
        entry_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return entry_id
    
    def save_analysis_result(self, analysis_type: str, result_data: Dict, 
                           risk_score: float = 0.0, risk_level: str = "low", 
                           parameters: Dict = None) -> int:
        """Save analysis result to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO analysis_results 
        (analysis_type, result_data, risk_score, risk_level, parameters)
        VALUES (?, ?, ?, ?, ?)
        ''', (
            analysis_type,
            json.dumps(result_data),
            risk_score,
            risk_level,
            json.dumps(parameters) if parameters else None
        ))
        
        result_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return result_id
    
    def get_log_entries(self, start_time: datetime = None, 
                       end_time: datetime = None, 
                       limit: int = 1000) -> List[Dict]:
        """Retrieve log entries with optional filters"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM log_entries WHERE 1=1"
        params = []
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert rows to dictionaries
        entries = []
        for row in rows:
            entry = dict(row)
            # Parse JSON fields
            if entry.get('query_params'):
                entry['query_params'] = json.loads(entry['query_params'])
            if entry.get('additional_data'):
                entry['additional_data'] = json.loads(entry['additional_data'])
            entries.append(entry)
        
        return entries
    
    def get_analysis_results(self, analysis_type: str = None, 
                           limit: int = 100) -> List[Dict]:
        """Retrieve analysis results"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if analysis_type:
            cursor.execute('''
            SELECT * FROM analysis_results 
            WHERE analysis_type = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
            ''', (analysis_type, limit))
        else:
            cursor.execute('''
            SELECT * FROM analysis_results 
            ORDER BY timestamp DESC 
            LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            result = dict(row)
            result['result_data'] = json.loads(result['result_data'])
            if result.get('parameters'):
                result['parameters'] = json.loads(result['parameters'])
            results.append(result)
        
        return results
