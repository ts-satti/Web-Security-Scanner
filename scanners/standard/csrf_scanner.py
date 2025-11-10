# scanners/standard/csrf_scanner.py
import time
from urllib.parse import urljoin
from ..base_scanner import SecurityScanner

class CSRFScanner(SecurityScanner):
    """Standard CSRF vulnerability scanner"""
    
    def run_scan(self):
        """Run focused CSRF scan"""
        try:
            print(f"[*] Starting CSRF scan for: {self.target_url}")
            self.update_progress(10, "🚀 Starting CSRF scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test CSRF vulnerabilities
            self.update_progress(50, "🛡️ Testing for CSRF vulnerabilities...")
            self.test_csrf()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating CSRF report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ CSRF scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] CSRF scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_csrf(self):
        """Enhanced CSRF vulnerability testing"""
        try:
            forms = self.extract_forms()
            csrf_found = False
            
            for form in forms:
                if self.check_stop_flag():
                    return
                # Check if paused and wait
                self.check_pause_flag()
                
                if form['method'] == 'post':
                    # Enhanced CSRF token detection
                    has_csrf = any(
                        'csrf' in field['name'].lower() or 
                        'token' in field['name'].lower() or
                        'nonce' in field['name'].lower() or
                        'authenticity' in field['name'].lower() or
                        'anticsrf' in field['name'].lower()
                        for field in form['inputs']
                    )
                    
                    if not has_csrf:
                        form_url = self._get_form_url(form)
                        self.vulnerabilities.append({
                            'category': 'CSRF',
                            'risk_level': 'Medium',
                            'title': 'Missing CSRF Protection',
                            'description': 'Form missing CSRF protection token',
                            'location': form_url,
                            'evidence': f'No CSRF token found in form with action: {form.get("action", "")}',
                            'recommendation': 'Implement CSRF tokens for all state-changing operations and use SameSite cookies'
                        })
                        csrf_found = True
                    
                    # Check SameSite cookie attribute
                    form_url = self._get_form_url(form)
                    success, response = self.safe_request('GET', form_url)
                    
                    if success:
                        for cookie in response.cookies:
                            cookie_str = str(cookie).lower()
                            if 'samesite' not in cookie_str:
                                self.vulnerabilities.append({
                                    'category': 'CSRF',
                                    'risk_level': 'Low',
                                    'title': 'Missing SameSite Cookie Attribute',
                                    'description': 'Cookie missing SameSite attribute which helps prevent CSRF',
                                    'location': form_url,
                                    'evidence': f'Cookie "{cookie.name}" missing SameSite attribute',
                                    'recommendation': 'Set SameSite=Strict or Lax for sensitive cookies'
                                })
                            elif 'samesite=none' in cookie_str:
                                self.vulnerabilities.append({
                                    'category': 'CSRF',
                                    'risk_level': 'Medium',
                                    'title': 'Weak SameSite Cookie Configuration',
                                    'description': 'Cookie has SameSite=None which provides no CSRF protection',
                                    'location': form_url,
                                    'evidence': f'Cookie "{cookie.name}" set to SameSite=None',
                                    'recommendation': 'Set SameSite=Strict or Lax for sensitive cookies instead of None'
                                })
            
            # If no CSRF vulnerabilities found, add an informational finding
            if not csrf_found:
                self.vulnerabilities.append({
                    'category': 'CSRF',
                    'risk_level': 'Info',
                    'title': 'CSRF Protection Implemented',
                    'description': 'Basic CSRF protection appears to be in place',
                    'location': self.target_url,
                    'evidence': 'CSRF tokens or SameSite cookies detected in forms',
                    'recommendation': 'Continue to monitor and implement additional CSRF protections as needed'
                })
                        
        except Exception as e:
            print(f"[-] CSRF test error: {e}")
    
    def _get_form_url(self, form):
        """Get full URL for form action"""
        form_action = form.get('action', '')
        return urljoin(self.target_url, form_action)