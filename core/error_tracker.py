"""
Error Tracking and Logging System
Stores recent errors/logs for debugging without relying on console
"""

from datetime import datetime
from collections import deque
from typing import Dict, List
import threading

class ErrorTracker:
    """Thread-safe error and log tracker"""
    
    def __init__(self, max_entries=1000):
        self.max_entries = max_entries
        self.logs = deque(maxlen=max_entries)
        self.lock = threading.Lock()
    
    def log(self, level: str, category: str, message: str, details: Dict = None):
        """Add a log entry"""
        with self.lock:
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': level,  # DEBUG, INFO, WARNING, ERROR, CRITICAL
                'category': category,  # AUTH, SCAN, DATABASE, API, etc.
                'message': message,
                'details': details or {}
            }
            self.logs.append(entry)
    
    def get_recent(self, limit: int = 100, level: str = None, category: str = None) -> List[Dict]:
        """Get recent log entries"""
        with self.lock:
            entries = list(self.logs)
        
        # Filter by level
        if level:
            entries = [e for e in entries if e['level'] == level]
        
        # Filter by category
        if category:
            entries = [e for e in entries if e['category'] == category]
        
        # Return most recent first
        return list(reversed(entries))[:limit]
    
    def get_stats(self) -> Dict:
        """Get error statistics"""
        with self.lock:
            entries = list(self.logs)
        
        stats = {
            'total': len(entries),
            'by_level': {},
            'by_category': {},
            'recent_errors': []
        }
        
        for entry in entries:
            # Count by level
            level = entry['level']
            stats['by_level'][level] = stats['by_level'].get(level, 0) + 1
            
            # Count by category
            category = entry['category']
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            
            # Collect recent errors
            if level in ['ERROR', 'CRITICAL']:
                stats['recent_errors'].append({
                    'timestamp': entry['timestamp'],
                    'category': entry['category'],
                    'message': entry['message']
                })
        
        # Limit recent errors
        stats['recent_errors'] = stats['recent_errors'][-20:]
        
        return stats
    
    def clear(self):
        """Clear all logs"""
        with self.lock:
            self.logs.clear()


# Global tracker instance
_tracker = ErrorTracker()

def get_tracker() -> ErrorTracker:
    """Get global error tracker"""
    return _tracker

def log_debug(category: str, message: str, **details):
    """Log debug message"""
    _tracker.log('DEBUG', category, message, details)

def log_info(category: str, message: str, **details):
    """Log info message"""
    _tracker.log('INFO', category, message, details)

def log_warning(category: str, message: str, **details):
    """Log warning"""
    _tracker.log('WARNING', category, message, details)

def log_error(category: str, message: str, **details):
    """Log error"""
    _tracker.log('ERROR', category, message, details)

def log_critical(category: str, message: str, **details):
    """Log critical error"""
    _tracker.log('CRITICAL', category, message, details)
