import time
import threading
from datetime import datetime

class ProgressManager:
    """Thread-safe progress management with detailed activity logging"""
    
    def __init__(self):
        self._progress_data = {}
        self._lock = threading.Lock()
    
    def update(self, scan_id, progress=None, status=None, current_task=None, vulnerabilities=0, security_score=100, detailed_message=None, risk_breakdown=None):
        """Update scan progress.

        Backwards-compatible: supports both calling styles used across the codebase:
        - update(scan_id, progress, status, current_task, vulnerabilities, security_score, detailed_message)
        - update(scan_id, status, current_task, vulnerabilities_found=.., ...)

        The function normalizes inputs and ensures `progress` and `vulnerabilities_found` are numeric.
        """
        with self._lock:
            # Normalize arguments for older call-sites that passed status as the second positional arg
            # Example legacy call: update(scan_id, 'initializing', 'Starting scan...')
            if isinstance(progress, str) and status is None:
                # shift: progress was actually status
                status = progress
                progress = None

            # Ensure a default progress entry exists and includes a progress key
            if scan_id not in self._progress_data:
                self._progress_data[scan_id] = {
                    'progress': 0,
                    'status': 'initializing',
                    'current_task': 'Starting scan...',
                    'vulnerabilities_found': 0,
                    'security_score': 100,
                    'last_update': time.time(),
                    'timestamp': datetime.utcnow().isoformat(),
                    'activity_log': [],
                    'risk_breakdown': {
                        'Critical': 0,
                        'High': 0,
                        'Medium': 0,
                        'Low': 0,
                        'Info': 0
                    }
                }
            
            # Add to activity log if detailed message provided
            if detailed_message:
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'message': detailed_message,
                    'type': 'info'
                }
                self._progress_data[scan_id]['activity_log'].append(log_entry)
            # Normalize numeric fields
            try:
                vuln_count = int(vulnerabilities)
            except Exception:
                vuln_count = 0

            try:
                prog_val = None if progress is None else int(progress)
            except Exception:
                prog_val = None

            # Normalize security_score safely (handle None or non-numeric)
            try:
                sec_score_val = int(security_score)
            except Exception:
                sec_score_val = 100

            # Update main progress data
            update_payload = {
                'status': status or self._progress_data[scan_id].get('status', 'running'),
                'current_task': current_task or self._progress_data[scan_id].get('current_task', 'Processing...'),
                'vulnerabilities_found': max(0, vuln_count),
                'security_score': max(0, min(100, sec_score_val)),
                'last_update': time.time(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Update risk breakdown if provided
            if risk_breakdown is not None:
                update_payload['risk_breakdown'] = risk_breakdown

            # Only set progress if provided (preserve existing otherwise)
            if prog_val is not None:
                update_payload['progress'] = max(0, min(100, prog_val))

            self._progress_data[scan_id].update(update_payload)
    
    def add_activity_log(self, scan_id, message, log_type='info'):
        """Add detailed activity log entry"""
        with self._lock:
            if scan_id not in self._progress_data:
                self._progress_data[scan_id] = self._default_progress(scan_id)
            
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'message': message,
                'type': log_type
            }
            self._progress_data[scan_id]['activity_log'].append(log_entry)
    
    def get(self, scan_id):
        """Get progress for a scan with full activity log"""
        with self._lock:
            if scan_id not in self._progress_data:
                return self._default_progress(scan_id)
            
            data = self._progress_data[scan_id].copy()
            # Ensure activity_log exists
            if 'activity_log' not in data:
                data['activity_log'] = []
            
            return data
    
    def _default_progress(self, scan_id):
        """Default progress structure"""
        return {
            'status': 'unknown',
            'current_task': 'Initializing...',
            'vulnerabilities_found': 0,
            'security_score': 100,
            'last_update': time.time(),
            'timestamp': datetime.utcnow().isoformat(),
            'activity_log': [{
                'timestamp': datetime.utcnow().isoformat(),
                'message': 'Scanner initialized and ready...',
                'type': 'info'
            }],
            'risk_breakdown': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0
            }
        }
    
    def delete(self, scan_id):
        """Remove progress data for a scan"""
        with self._lock:
            if scan_id in self._progress_data:
                del self._progress_data[scan_id]
    
    def cleanup_old(self, max_age=3600):
        """Clean up progress data older than max_age seconds"""
        with self._lock:
            current_time = time.time()
            expired_scans = [
                scan_id for scan_id, data in self._progress_data.items()
                if current_time - data.get('last_update', 0) > max_age
            ]
            for scan_id in expired_scans:
                del self._progress_data[scan_id]

# Global progress manager instance
progress_manager = ProgressManager()