# scanners/base_scanner.py
import requests
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import concurrent.futures
from utils.helpers import progress_manager

class SecurityScanner:
    """Base security scanner class"""
    
    def __init__(self, target_url, scan_id, config=None):
        self.target_url = target_url
        self.scan_id = scan_id
        self.config = config or {}
        self.vulnerabilities = []
        self.session = requests.Session()
        self.stop_flag = False
        self.current_phase = "Initializing"
        
        # Configure session
        self.session.timeout = self.config.get('REQUEST_TIMEOUT', 10)
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
    
    def log_activity(self, message, log_type='info'):
        """Log detailed activity with timestamp"""
        progress_manager.add_activity_log(self.scan_id, message, log_type)
        print(f"[SCAN {self.scan_id}] {message}")
    
    def update_progress(self, phase, message=None, vulnerabilities_found=None, progress_value=None):
        """Update scan progress and activity log.

        Backward compatible with two calling styles:
        - update_progress(10, "Starting ...")  -> numeric progress + textual task
        - update_progress("Testing XSS ...")   -> textual task (no progress change unless progress_value provided)

        If the first argument ``phase`` looks numeric (int/float or digit string),
        it is treated as a progress value only and will NOT be logged as a phase
        name. In that case, the current task will be set from ``message`` if
        provided, otherwise preserved from the previous value.
        """
        if vulnerabilities_found is None:
            vulnerabilities_found = len(self.vulnerabilities)

        aggregate_provider = None
        try:
            aggregate_provider = self.config.get('aggregate_vulnerability_provider')
        except AttributeError:
            aggregate_provider = None

        if aggregate_provider:
            try:
                aggregate_value = aggregate_provider()
                if aggregate_value is not None:
                    vulnerabilities_found = max(vulnerabilities_found, int(aggregate_value))
            except Exception:
                # Ignore aggregation errors to avoid breaking scan flow
                pass

        # Determine whether caller passed a numeric progress as first arg
        is_numeric_phase = isinstance(phase, (int, float)) or (
            isinstance(phase, str) and phase.isdigit()
        )

        # Coerce to int progress if numeric; prefer explicit progress_value when given
        if is_numeric_phase and progress_value is None:
            try:
                progress_value = int(float(phase))
            except Exception:
                progress_value = None

        # Derive a human-friendly task label
        message_text = str(message) if message is not None and message != '' else None
        if is_numeric_phase:
            # Do not treat numeric as a phase label; preserve current label unless message provided
            phase_label = message_text if message_text else (self.current_phase or 'Processing...')
            log_phase_change = (message_text is not None and phase_label != self.current_phase)
        else:
            phase_label = str(phase)
            log_phase_change = (phase_label != self.current_phase)

        # Calculate security score (simple heuristic based on findings)
        security_score = max(0, 100 - (vulnerabilities_found * 2))
        
        # Calculate risk breakdown
        risk_breakdown = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in self.vulnerabilities:
            risk_level = vuln.get('risk_level', 'Info')
            if risk_level in risk_breakdown:
                risk_breakdown[risk_level] += 1

        # Log phase changes once to avoid noise
        if log_phase_change:
            self.log_activity(f"🔄 Entering phase: {phase_label}")
            self.current_phase = phase_label

        # Log additional message when supplied
        # Log the extra message only when it's not exactly the same as the phase label
        if message_text and message_text != phase_label:
            self.log_activity(message_text)

        # Respect pause state when reporting status
        from app import running_scans
        is_paused = (
            self.scan_id in running_scans and
            running_scans[self.scan_id].get('paused', False)
        )

        current_status = 'paused' if is_paused else 'running'

        progress_manager.update(
            self.scan_id,
            progress=progress_value,
            status=current_status,
            current_task=phase_label,
            vulnerabilities=vulnerabilities_found,
            security_score=security_score,
            detailed_message=message_text,
            risk_breakdown=risk_breakdown
        )
    
    def check_stop_flag(self):
        """Check if scan should stop"""
        from app import running_scans
        # First, respect the centralized running_scans stop flag when available
        try:
            if self.scan_id in running_scans and running_scans[self.scan_id].get('stop_flag'):
                return True
        except Exception:
            pass

        # Fall back to instance-level stop flag (set by stop_scan()) so that
        # the scanner can still stop even if running_scans entry is missing.
        return bool(getattr(self, 'stop_flag', False))
    
    def check_pause_flag(self):
        """Check if scan is paused and wait if paused"""
        from app import running_scans
        import time
        while (self.scan_id in running_scans and 
               running_scans[self.scan_id].get('paused', False) and 
               not running_scans[self.scan_id].get('stop_flag', False)):
            time.sleep(0.5)  # Wait 0.5 seconds before checking again
        # Return True if still paused (shouldn't happen unless stopped)
        return (self.scan_id in running_scans and 
                running_scans[self.scan_id].get('paused', False))
    
    def check_stop_or_pause(self):
        """Check if scan should stop, and if paused, wait until resumed"""
        if self.check_stop_flag():
            return True
        self.check_pause_flag()  # Wait if paused
        return False
    
    def stop_scan(self):
        """Stop the scan"""
        self.stop_flag = True
        # Attempt to close the HTTP session to interrupt any in-flight requests.
        try:
            if hasattr(self, 'session') and self.session:
                try:
                    self.session.close()
                except Exception:
                    pass
        except Exception:
            pass

        self.log_activity("🛑 Scan stopped by user", 'error')
    
    def safe_request(self, method, url, **kwargs):
        """Make safe HTTP request with detailed logging"""
        try:
            # Check pause immediately before making request - critical for responsiveness
            if self.check_stop_flag():
                return False, "Scan stopped"
            self.check_pause_flag()
            
            # Double-check pause right before the actual request call
            if self.check_stop_flag():
                return False, "Scan stopped"
            if (self.scan_id in self._get_running_scans() and 
                self._get_running_scans()[self.scan_id].get('paused', False)):
                # If paused during check, wait and re-check
                self.check_pause_flag()
            
            # Add current phase/context to HTTP activity logs so users know which section triggered the request
            context = self.current_phase if getattr(self, 'current_phase', None) else 'Scanning'
            self.log_activity(f"🌐 [{context}] Making {method} request to: {url}")
            timeout = self.config.get('REQUEST_TIMEOUT', 10)
            response = self.session.request(method, url, timeout=timeout, **kwargs)
            
            # Check pause immediately after request completes
            if self.check_stop_flag():
                return True, response  # Return response but indicate stopped
            self.check_pause_flag()
            
            self.log_activity(f"✅ [{context}] {method} request completed - Status: {response.status_code}")
            return True, response
        except requests.exceptions.RequestException as e:
            # Check pause even on error
            self.check_pause_flag()
            context = self.current_phase if getattr(self, 'current_phase', None) else 'Scanning'
            self.log_activity(f"❌ [{context}] Request failed: {str(e)}", 'error')
            return False, str(e)
    
    def _get_running_scans(self):
        """Helper to get running_scans dict"""
        from app import running_scans
        return running_scans
    
    def extract_forms(self):
        """Extract all forms from the target URL with logging"""
        self.log_activity("🔍 Extracting forms from target page...")
        success, response = self.safe_request('GET', self.target_url)
        if not success:
            self.log_activity("❌ Failed to extract forms", 'error')
            return []
        
        forms = []
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        self.log_activity(f"📝 Found {len(forms)} forms on the target page")
        return forms
    
    def test_form_submission(self, form, payloads, category):
        """Test form submission with various payloads"""
        vulnerabilities = []
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        target_url = urljoin(self.target_url, form_action)
        
        for payload_name, payload in payloads.items():
            if self.check_stop_flag():
                return vulnerabilities
            
            # Check if paused and wait
            self.check_pause_flag()
            
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'search', 'hidden', 'textarea']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field.get('value', '')
            
            try:
                if form_method == 'post':
                    success, response = self.safe_request('POST', target_url, data=data)
                else:
                    success, response = self.safe_request('GET', target_url, params=data)
                
                if success and self.detect_vulnerability(response, payload_name, category):
                    vulnerabilities.append({
                        'category': category,
                        'risk_level': self.get_risk_level(category, payload_name),
                        'title': f'{category} Vulnerability - {payload_name}',
                        'description': f'Potential {category} vulnerability detected',
                        'location': target_url,
                        'payload': payload,
                        'evidence': 'Vulnerability pattern matched in response',
                        'recommendation': self.get_recommendation(category)
                    })
                    # Update aggregate state immediately so UI reflects findings in real-time
                    try:
                        # vulnerabilities is local; self.vulnerabilities will be extended by caller
                        current_total = len(self.vulnerabilities) + len(vulnerabilities)
                        # Report progress with updated vulnerability count (no progress percent change)
                        self.update_progress(self.current_phase, f"Found {current_total} vulnerabilities", vulnerabilities_found=current_total)
                    except Exception:
                        # Non-fatal: continue scanning even if progress update fails
                        pass
                
                # Check pause during delay - sleep in small increments to check frequently
                delay = self.config.get('REQUEST_DELAY', 0.5)
                sleep_increment = 0.1
                remaining = delay
                while remaining > 0:
                    if self.check_stop_flag():
                        return vulnerabilities
                    self.check_pause_flag()
                    sleep_time = min(sleep_increment, remaining)
                    time.sleep(sleep_time)
                    remaining -= sleep_time
                
            except Exception as e:
                # Check pause even on exception
                self.check_pause_flag()
                continue
        
        return vulnerabilities
    
    def detect_vulnerability(self, response, payload_name, category):
        """Enhanced vulnerability detection patterns"""
        if not response:
            return False
        
        text = response.text.lower()
        
        if category == 'SQL Injection':
            # Enhanced SQL injection indicators
            sql_indicators = [
                'sql syntax', 'mysql_fetch', 'ora-', 'warning:',
                'mysql error', 'syntax error', 'unclosed quotation',
                'you have an error in your sql', 'mysql_result', 
                'postgresql error', 'microsoft odbc', 'sqlite3',
                'pdo exception', 'database error', 'sql statement'
            ]
            return any(indicator in text for indicator in sql_indicators)
        
        elif category == 'XSS':
            # Enhanced XSS detection
            xss_indicators = [
                '<script>alert', 'onerror=', 'onload=', 'onclick=',
                'javascript:', 'vbscript:', '<iframe', '<object',
                '<embed', '<svg', '<math', 'expression('
            ]
            return any(indicator in text for indicator in xss_indicators) or payload_name in text
        
        return False
    
    def get_risk_level(self, category, payload_name):
        """Get risk level for vulnerability"""
        risk_mapping = {
            'SQL Injection': 'High',
            'XSS': 'Medium',
            'CSRF': 'Medium',
            'Information Disclosure': 'Low',
            'Security Headers': 'Low',
            'Open Port': 'Medium' if '21' in payload_name or '22' in payload_name else 'Low'
        }
        return risk_mapping.get(category, 'Medium')
    
    def get_recommendation(self, category):
        """Get recommendation for vulnerability"""
        recommendations = {
            'SQL Injection': 'Use parameterized queries and input validation',
            'XSS': 'Implement output encoding and Content Security Policy',
            'CSRF': 'Use anti-CSRF tokens and SameSite cookies',
            'Information Disclosure': 'Remove sensitive information from responses'
        }
        return recommendations.get(category, 'Implement proper security controls')
    
    def calculate_security_score(self):
        """Calculate security score based on vulnerabilities found"""
        base_score = 100
        
        for vuln in self.vulnerabilities:
            risk_weight = {
                'Critical': 20,
                'High': 15,
                'Medium': 8,
                'Low': 3,
                'Info': 1
            }.get(vuln['risk_level'], 5)
            
            base_score -= risk_weight
        
        return max(0, base_score)
    
    def _build_results(self, status, security_score=None, error_message=None):
        """Build results dictionary"""
        if security_score is None:
            security_score = self.calculate_security_score()
        
        # Enhanced results with risk breakdown
        risk_breakdown = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in self.vulnerabilities:
            risk_level = vuln.get('risk_level', 'Info')
            if risk_level in risk_breakdown:
                risk_breakdown[risk_level] += 1
        
        return {
            'status': status,
            'target_url': self.target_url,
            'vulnerabilities': self.vulnerabilities,
            'total_vulnerabilities': len(self.vulnerabilities),
            'security_score': security_score,
            'risk_breakdown': risk_breakdown,
            'high_count': risk_breakdown['High'],
            'critical_count': risk_breakdown['Critical'],
            'error_message': error_message,
            'scan_timestamp': time.time()
        }
    
    def run_scan(self):
        """Run security scan - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement run_scan method")