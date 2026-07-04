"""
Centralized Enterprise Logger
Supports standard structured JSON logging and security audit logging.
"""

import os
import json
import logging
from datetime import datetime

class EnterpriseLogger:
    """Structured JSON & Audit logger for professional operations"""
    
    _initialized = False
    _log_file = None
    _audit_file = None
    _structured = True
    
    @classmethod
    def setup(cls, config):
        """Configure logging parameters from settings"""
        if cls._initialized:
            return
            
        cls._structured = config.get('logging.structured', True)
        log_path = config.get('logging.log_file', 'logs/hacktheweb.log')
        audit_path = config.get('logging.audit_file', 'logs/audit.log')
        
        # Resolve log directory relative to workspace root
        base_dir = config.base_dir
        cls._log_file = base_dir / log_path
        cls._audit_file = base_dir / audit_path
        
        # Ensure log directories exist
        cls._log_file.parent.mkdir(parents=True, exist_ok=True)
        cls._audit_file.parent.mkdir(parents=True, exist_ok=True)
        
        cls._initialized = True

    @classmethod
    def log(cls, level: str, message: str, extra: dict = None):
        """Write structured log message"""
        if not cls._initialized:
            # Fallback if setup hasn't run
            print(f"[{level.upper()}] {message}")
            return
            
        timestamp = datetime.utcnow().isoformat() + 'Z'
        log_data = {
            'timestamp': timestamp,
            'level': level.upper(),
            'message': message
        }
        if extra:
            log_data.update(extra)
            
        if cls._structured:
            log_line = json.dumps(log_data)
        else:
            extra_str = f" | {json.dumps(extra)}" if extra else ""
            log_line = f"[{timestamp}] [{level.upper()}] {message}{extra_str}"
            
        with open(cls._log_file, 'a', encoding='utf-8') as f:
            f.write(log_line + '\n')
            
        # Optional CLI mirror for error/warning/info
        if level.lower() in ['error', 'critical', 'warning']:
            print(f"[!] {message}")

    @classmethod
    def audit(cls, action: str, target: str, status: str, details: dict = None):
        """Write secure audit log entries for activity correlation"""
        if not cls._initialized:
            return
            
        timestamp = datetime.utcnow().isoformat() + 'Z'
        audit_data = {
            'timestamp': timestamp,
            'action': action,
            'target': target,
            'status': status
        }
        if details:
            audit_data['details'] = details
            
        audit_line = json.dumps(audit_data)
        with open(cls._audit_file, 'a', encoding='utf-8') as f:
            f.write(audit_line + '\n')
