# scanners/advanced/enhanced_csrf_scanner.py
import time
import random
import string
from urllib.parse import urljoin, urlparse
from ..base_scanner import SecurityScanner

class EnhancedCSRFScanner(SecurityScanner):
    """Advanced CSRF vulnerability scanner"""
    
    def run_scan(self):
        """Run comprehensive CSRF scan"""
        try:
            print(f"[*] Starting Advanced CSRF scan for: {self.target_url}")
            self.update_progress(10, "🚀 Initializing advanced CSRF scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 1: Basic CSRF detection
            self.update_progress(20, "🔍 Scanning for basic CSRF vulnerabilities...")
            self.test_basic_csrf()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 2: Advanced CSRF techniques
            self.update_progress(40, "⚡ Testing advanced CSRF vectors...")
            self.test_advanced_csrf()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 3: CSRF token analysis
            self.update_progress(60, "🔑 Analyzing CSRF token implementations...")
            self.analyze_csrf_tokens()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 4: CORS & Origin validation
            self.update_progress(75, "🌐 Testing CORS & origin validation...")
            self.test_cors_origin_validation()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 5: Session & cookie analysis
            self.update_progress(85, "🍪 Analyzing session security...")
            self.analyze_session_security()
            
            # Finalize
            self.update_progress(95, "📊 Generating comprehensive CSRF report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Advanced CSRF scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Advanced CSRF scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_basic_csrf(self):
        """Enhanced basic CSRF vulnerability testing"""
        try:
            forms = self.extract_forms()
            csrf_protected_forms = 0
            total_forms = len(forms)
            
            for form in forms:
                if self.check_stop_flag():
                    return
                self.check_pause_flag()
                
                form_url = self._get_form_url(form)
                form_method = form['method'].lower()
                
                # Skip GET forms for state-changing operations (unless dangerous)
                if form_method == 'get' and self._is_state_changing_form(form):
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'High',
                        'title': 'State-changing GET Form',
                        'description': 'Form uses GET method for potentially state-changing operation',
                        'location': form_url,
                        'evidence': f'GET form with action: {form.get("action", "")} containing sensitive fields',
                        'recommendation': 'Change form method to POST and implement CSRF protection'
                    })
                
                if form_method in ['post', 'put', 'delete']:
                    csrf_analysis = self._analyze_csrf_protection(form)
                    
                    if not csrf_analysis['protected']:
                        self.vulnerabilities.append({
                            'category': 'CSRF',
                            'risk_level': 'High',
                            'title': 'Missing CSRF Protection',
                            'description': f'{form_method.upper()} form missing CSRF protection',
                            'location': form_url,
                            'evidence': f'No CSRF token found in {form_method.upper()} form',
                            'recommendation': 'Implement CSRF tokens, use SameSite cookies, and validate Origin/Referer headers'
                        })
                    else:
                        csrf_protected_forms += 1
                        
                        # Test token strength if present
                        if csrf_analysis.get('token_found'):
                            self._test_csrf_token_strength(form, csrf_analysis['token_field'])
            
            # Report overall CSRF protection status
            protection_rate = (csrf_protected_forms / total_forms * 100) if total_forms > 0 else 100
            
            if protection_rate < 80:
                self.vulnerabilities.append({
                    'category': 'CSRF',
                    'risk_level': 'Medium',
                    'title': 'Inconsistent CSRF Protection',
                    'description': f'Only {protection_rate:.1f}% of forms have CSRF protection',
                    'location': self.target_url,
                    'evidence': f'{csrf_protected_forms}/{total_forms} forms protected',
                    'recommendation': 'Ensure all state-changing forms have CSRF protection'
                })
                        
        except Exception as e:
            print(f"[-] Basic CSRF test error: {e}")
    
    def test_advanced_csrf(self):
        """Test advanced CSRF attack vectors"""
        try:
            # Test JSON-based CSRF
            self._test_json_csrf()
            
            # Test Flash-based CSRF
            self._test_flash_csrf()
            
            # Test CSRF via file upload
            self._test_file_upload_csrf()
            
            # Test CSRF with different content types
            self._test_content_type_csrf()
            
        except Exception as e:
            print(f"[-] Advanced CSRF test error: {e}")
    
    def analyze_csrf_tokens(self):
        """Analyze CSRF token implementation strength"""
        try:
            forms = self.extract_forms()
            
            for form in forms:
                if self.check_stop_flag():
                    return
                self.check_pause_flag()
                
                csrf_analysis = self._analyze_csrf_protection(form)
                
                if csrf_analysis.get('token_found'):
                    token_field = csrf_analysis['token_field']
                    
                    # Test token predictability
                    self._test_token_predictability(form, token_field)
                    
                    # Test token reuse
                    self._test_token_reuse(form, token_field)
                    
                    # Test token binding
                    self._test_token_binding(form, token_field)
                    
        except Exception as e:
            print(f"[-] CSRF token analysis error: {e}")
    
    def test_cors_origin_validation(self):
        """Test CORS and origin/referer validation"""
        try:
            # Test CORS misconfiguration
            self._test_cors_misconfig()
            
            # Test Origin header validation
            self._test_origin_validation()
            
            # Test Referer header validation
            self._test_referer_validation()
            
        except Exception as e:
            print(f"[-] CORS/Origin test error: {e}")
    
    def analyze_session_security(self):
        """Analyze session and cookie security"""
        try:
            # Test SameSite cookie attributes comprehensively
            self._test_samesite_cookies()
            
            # Test session fixation vulnerabilities
            self._test_session_fixation()
            
            # Test secure flag on cookies
            self._test_cookie_security_flags()
            
        except Exception as e:
            print(f"[-] Session security analysis error: {e}")
    
    def _analyze_csrf_protection(self, form):
        """Comprehensive CSRF protection analysis"""
        analysis = {
            'protected': False,
            'token_found': False,
            'token_field': None,
            'protection_types': []
        }
        
        csrf_patterns = [
            'csrf', 'token', 'nonce', 'authenticity', 'anticsrf',
            '_token', 'csrf_token', 'csrfmiddlewaretoken', 'yii_csrf_token',
            'laravel_token', 'symfony_token', 'wordpress_nonce'
        ]
        
        # Check for CSRF tokens in form inputs
        for field in form['inputs']:
            field_name = field['name'].lower()
            field_value = field.get('value', '')
            
            for pattern in csrf_patterns:
                if pattern in field_name:
                    analysis['protected'] = True
                    analysis['token_found'] = True
                    analysis['token_field'] = field
                    analysis['protection_types'].append('form_token')
                    break
            
            # Check for hidden fields with token-like values
            if field.get('type') == 'hidden' and len(field_value) >= 16:
                if any(char in field_value for char in ['/', '+', '=']):  # Base64-like
                    analysis['protected'] = True
                    analysis['token_found'] = True
                    analysis['token_field'] = field
                    analysis['protection_types'].append('hidden_token')
        
        # Check for custom headers
        if any(header.lower().startswith(('x-csrf-token', 'x-xsrf-token')) 
               for header in form.get('headers', {})):
            analysis['protected'] = True
            analysis['protection_types'].append('custom_header')
        
        # Check for double submit cookie pattern
        form_url = self._get_form_url(form)
        success, response = self.safe_request('GET', form_url)
        if success:
            for cookie in response.cookies:
                if any(pattern in cookie.name.lower() for pattern in csrf_patterns):
                    analysis['protected'] = True
                    analysis['protection_types'].append('double_submit_cookie')
        
        return analysis
    
    def _is_state_changing_form(self, form):
        """Check if form performs state-changing operations"""
        state_changing_patterns = [
            'delete', 'remove', 'update', 'modify', 'create', 'add',
            'edit', 'save', 'submit', 'post', 'comment', 'message',
            'transfer', 'payment', 'order', 'purchase', 'bid'
        ]
        
        form_action = form.get('action', '').lower()
        form_id = form.get('id', '').lower()
        form_class = form.get('class', '').lower()
        
        # Check input names for state-changing operations
        for field in form['inputs']:
            field_name = field['name'].lower()
            field_type = field.get('type', '').lower()
            
            if field_type in ['submit', 'button']:
                field_value = field.get('value', '').lower()
                if any(pattern in field_value for pattern in state_changing_patterns):
                    return True
            
            if any(pattern in field_name for pattern in ['delete', 'remove', 'update']):
                return True
        
        return any(pattern in form_action for pattern in state_changing_patterns) or \
               any(pattern in form_id for pattern in state_changing_patterns) or \
               any(pattern in form_class for pattern in state_changing_patterns)
    
    def _test_csrf_token_strength(self, form, token_field):
        """Test CSRF token strength and characteristics"""
        token_value = token_field.get('value', '')
        
        # Check token length
        if len(token_value) < 16:
            form_url = self._get_form_url(form)
            self.vulnerabilities.append({
                'category': 'CSRF',
                'risk_level': 'Medium',
                'title': 'Weak CSRF Token',
                'description': 'CSRF token appears to be too short',
                'location': form_url,
                'evidence': f'Token length: {len(token_value)} characters',
                'recommendation': 'Use longer, cryptographically secure tokens (minimum 16 bytes)'
            })
        
        # Check token entropy
        entropy = self._calculate_entropy(token_value)
        if entropy < 3.0:  # Low entropy threshold
            form_url = self._get_form_url(form)
            self.vulnerabilities.append({
                'category': 'CSRF',
                'risk_level': 'Medium',
                'title': 'Predictable CSRF Token',
                'description': 'CSRF token has low entropy and may be predictable',
                'location': form_url,
                'evidence': f'Token entropy: {entropy:.2f}',
                'recommendation': 'Use cryptographically secure random number generators for token generation'
            })
    
    def _test_token_predictability(self, form, token_field):
        """Test if CSRF tokens are predictable"""
        # Attempt to collect multiple tokens to check for patterns
        form_url = self._get_form_url(form)
        
        tokens = []
        for _ in range(3):
            if self.check_stop_flag():
                return
            success, response = self.safe_request('GET', form_url)
            if success:
                # Extract token from response
                # This would require parsing the form again from response
                pass
        
        # Analyze token patterns if multiple tokens collected
        if len(tokens) >= 2:
            # Check for sequential patterns
            # Check for time-based patterns
            # Check for user-specific patterns
            pass
    
    def _test_token_reuse(self, form, token_field):
        """Test if CSRF tokens can be reused"""
        form_url = self._get_form_url(form)
        form_data = self._build_form_data(form)
        
        # Submit form once
        success, response1 = self.safe_request(form['method'], form_url, data=form_data)
        
        if success and response1.status_code in [200, 302]:
            # Try to submit same form data again
            success, response2 = self.safe_request(form['method'], form_url, data=form_data)
            
            if success and response2.status_code in [200, 302]:
                self.vulnerabilities.append({
                    'category': 'CSRF',
                    'risk_level': 'High',
                    'title': 'CSRF Token Reuse',
                    'description': 'CSRF token can be reused multiple times',
                    'location': form_url,
                    'evidence': 'Same token accepted in multiple requests',
                    'recommendation': 'Implement one-time use tokens or short token timeouts'
                })
    
    def _test_token_binding(self, form, token_field):
        """Test if CSRF tokens are properly bound to session"""
        # This would require testing with different sessions
        # Implementation depends on session management capabilities
        pass
    
    def _test_json_csrf(self):
        """Test for JSON-based CSRF vulnerabilities"""
        forms = self.extract_forms()
        
        for form in forms:
            if self.check_stop_flag():
                return
            
            if form['method'].lower() == 'post':
                form_url = self._get_form_url(form)
                
                # Test with JSON content-type but form data
                json_headers = {'Content-Type': 'application/json'}
                form_data = self._build_form_data(form)
                
                success, response = self.safe_request(
                    'POST', form_url, 
                    data=form_data,
                    headers=json_headers
                )
                
                if success and response.status_code in [200, 302]:
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'Medium',
                        'title': 'JSON CSRF Possible',
                        'description': 'Application accepts form data with JSON content-type',
                        'location': form_url,
                        'evidence': 'POST request with form data and JSON content-type was accepted',
                        'recommendation': 'Validate content-type strictly and implement CSRF protection for JSON endpoints'
                    })
    
    def _test_flash_csrf(self):
        """Test for Flash-based CSRF vulnerabilities"""
        # Check for crossdomain.xml policy file
        crossdomain_url = urljoin(self.target_url, '/crossdomain.xml')
        success, response = self.safe_request('GET', crossdomain_url)
        
        if success and response.status_code == 200:
            # Analyze crossdomain policy for overly permissive settings
            if 'allow-access-from domain="*"' in response.text:
                self.vulnerabilities.append({
                    'category': 'CSRF',
                    'risk_level': 'High',
                    'title': 'Permissive Flash Cross-Domain Policy',
                    'description': 'Flash crossdomain.xml allows access from any domain',
                    'location': crossdomain_url,
                    'evidence': 'allow-access-from domain="*" found in crossdomain.xml',
                    'recommendation': 'Restrict Flash cross-domain access to trusted domains only'
                })
    
    def _test_file_upload_csrf(self):
        """Test CSRF in file upload functionality"""
        forms = self.extract_forms()
        
        for form in forms:
            if self.check_stop_flag():
                return
            
            has_file_upload = any(
                field.get('type') == 'file' for field in form['inputs']
            )
            
            if has_file_upload:
                form_url = self._get_form_url(form)
                csrf_analysis = self._analyze_csrf_protection(form)
                
                if not csrf_analysis['protected']:
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'High',
                        'title': 'File Upload CSRF',
                        'description': 'File upload form missing CSRF protection',
                        'location': form_url,
                        'evidence': 'File upload capability without CSRF tokens',
                        'recommendation': 'Implement CSRF protection for all file upload forms'
                    })
    
    def _test_content_type_csrf(self):
        """Test CSRF with different content-type manipulations"""
        forms = self.extract_forms()
        
        for form in forms:
            if self.check_stop_flag():
                return
            
            if form['method'].lower() == 'post':
                form_url = self._get_form_url(form)
                
                # Test with multipart/form-data
                multipart_headers = {'Content-Type': 'multipart/form-data'}
                form_data = self._build_form_data(form)
                
                success, response = self.safe_request(
                    'POST', form_url,
                    data=form_data,
                    headers=multipart_headers
                )
                
                # If successful without proper CSRF protection, log finding
                csrf_analysis = self._analyze_csrf_protection(form)
                if success and response.status_code in [200, 302] and not csrf_analysis['protected']:
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'Medium',
                        'title': 'Content-Type Manipulation CSRF',
                        'description': 'Form accepts requests with manipulated content-types',
                        'location': form_url,
                        'evidence': 'Request with modified Content-Type header was accepted',
                        'recommendation': 'Validate content-type headers and implement CSRF protection'
                    })
    
    def _test_cors_misconfig(self):
        """Test for CORS misconfigurations"""
        test_endpoints = [self.target_url, urljoin(self.target_url, '/api/'), urljoin(self.target_url, '/v1/')]
        
        for endpoint in test_endpoints:
            if self.check_stop_flag():
                return
            
            # Test CORS with arbitrary origin
            test_origin = 'https://evil-attacker.com'
            cors_headers = {'Origin': test_origin}
            
            success, response = self.safe_request('OPTIONS', endpoint, headers=cors_headers)
            
            if success:
                # Check for overly permissive CORS headers
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*' and acac.lower() == 'true':
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'High',
                        'title': 'Overly Permissive CORS',
                        'description': 'CORS configuration allows any origin with credentials',
                        'location': endpoint,
                        'evidence': f'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
                        'recommendation': 'Restrict CORS origins to trusted domains and avoid using wildcards with credentials'
                    })
                elif acao == test_origin and acac.lower() == 'true':
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'High',
                        'title': 'Reflected Origin CORS',
                        'description': 'CORS configuration reflects arbitrary origins with credentials',
                        'location': endpoint,
                        'evidence': f'Origin {test_origin} reflected in Access-Control-Allow-Origin with credentials',
                        'recommendation': 'Validate and whitelist CORS origins instead of reflecting arbitrary values'
                    })
    
    def _test_origin_validation(self):
        """Test Origin header validation"""
        forms = self.extract_forms()
        
        for form in forms:
            if self.check_stop_flag():
                return
            
            if form['method'].lower() in ['post', 'put', 'delete']:
                form_url = self._get_form_url(form)
                form_data = self._build_form_data(form)
                
                # Test with spoofed Origin header
                spoofed_origin = 'https://attacker.com'
                spoofed_headers = {'Origin': spoofed_origin}
                
                success, response = self.safe_request(
                    form['method'], form_url,
                    data=form_data,
                    headers=spoofed_headers
                )
                
                # If request succeeds with spoofed origin, origin validation might be weak
                if success and response.status_code in [200, 302]:
                    csrf_analysis = self._analyze_csrf_protection(form)
                    if not csrf_analysis['protected']:
                        self.vulnerabilities.append({
                            'category': 'CSRF',
                            'risk_level': 'Medium',
                            'title': 'Weak Origin Validation',
                            'description': 'Request with spoofed Origin header was accepted',
                            'location': form_url,
                            'evidence': f'Request with Origin: {spoofed_origin} was successful',
                            'recommendation': 'Implement strict Origin header validation for all state-changing requests'
                        })
    
    def _test_referer_validation(self):
        """Test Referer header validation"""
        forms = self.extract_forms()
        
        for form in forms:
            if self.check_stop_flag():
                return
            
            if form['method'].lower() in ['post', 'put', 'delete']:
                form_url = self._get_form_url(form)
                form_data = self._build_form_data(form)
                
                # Test with missing Referer header
                headers = {'Referer': ''}
                
                success, response = self.safe_request(
                    form['method'], form_url,
                    data=form_data,
                    headers=headers
                )
                
                # If request succeeds without Referer, referer validation might be missing
                if success and response.status_code in [200, 302]:
                    csrf_analysis = self._analyze_csrf_protection(form)
                    if not csrf_analysis['protected']:
                        self.vulnerabilities.append({
                            'category': 'CSRF',
                            'risk_level': 'Low',
                            'title': 'Missing Referer Validation',
                            'description': 'Request without Referer header was accepted',
                            'location': form_url,
                            'evidence': 'Request with empty Referer header was successful',
                            'recommendation': 'Implement Referer header validation as secondary CSRF protection'
                        })
    
    def _test_samesite_cookies(self):
        """Comprehensive SameSite cookie testing"""
        success, response = self.safe_request('GET', self.target_url)
        
        if success:
            for cookie in response.cookies:
                cookie_str = str(cookie).lower()
                cookie_name = cookie.name
                
                # Check for missing SameSite attribute
                if 'samesite' not in cookie_str:
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'Medium',
                        'title': 'Missing SameSite Cookie Attribute',
                        'description': f'Cookie "{cookie_name}" missing SameSite attribute',
                        'location': self.target_url,
                        'evidence': f'Cookie "{cookie_name}" has no SameSite attribute set',
                        'recommendation': 'Set SameSite=Lax or Strict for session cookies'
                    })
                
                # Check for weak SameSite=None without Secure
                elif 'samesite=none' in cookie_str and 'secure' not in cookie_str:
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'High',
                        'title': 'Insecure SameSite=None Cookie',
                        'description': f'Cookie "{cookie_name}" has SameSite=None without Secure flag',
                        'location': self.target_url,
                        'evidence': f'Cookie "{cookie_name}" set to SameSite=None but missing Secure flag',
                        'recommendation': 'Either set SameSite=Lax/Strict or ensure Secure flag is set with SameSite=None'
                    })
                
                # Check for SameSite=None on sensitive cookies
                elif 'samesite=none' in cookie_str and any(pattern in cookie_name.lower() 
                      for pattern in ['session', 'auth', 'token', 'csrf']):
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'Medium',
                        'title': 'Sensitive Cookie with SameSite=None',
                        'description': f'Sensitive cookie "{cookie_name}" allows cross-site requests',
                        'location': self.target_url,
                        'evidence': f'Sensitive cookie "{cookie_name}" set to SameSite=None',
                        'recommendation': 'Consider using SameSite=Lax or Strict for sensitive cookies'
                    })
    
    def _test_session_fixation(self):
        """Test for session fixation vulnerabilities"""
        # Get initial session
        success1, response1 = self.safe_request('GET', self.target_url)
        
        if success1:
            session_cookies = []
            for cookie in response1.cookies:
                if any(pattern in cookie.name.lower() for pattern in ['session', 'sessid', 'auth']):
                    session_cookies.append(cookie)
            
            # If session cookies are set without regeneration on login, might be vulnerable
            if session_cookies:
                self.vulnerabilities.append({
                    'category': 'CSRF',
                    'risk_level': 'Info',
                    'title': 'Session Cookies Detected',
                    'description': 'Session management cookies found',
                    'location': self.target_url,
                    'evidence': f'Found {len(session_cookies)} session-related cookies',
                    'recommendation': 'Ensure session regeneration on authentication and use secure cookie attributes'
                })
    
    def _test_cookie_security_flags(self):
        """Test cookie security flags"""
        success, response = self.safe_request('GET', self.target_url)
        
        if success:
            for cookie in response.cookies:
                cookie_str = str(cookie).lower()
                cookie_name = cookie.name
                
                security_issues = []
                
                # Check for missing Secure flag on HTTPS sites
                if self.target_url.startswith('https://') and 'secure' not in cookie_str:
                    security_issues.append('missing Secure flag')
                
                # Check for missing HttpOnly flag on session cookies
                if any(pattern in cookie_name.lower() for pattern in ['session', 'auth', 'token']):
                    if 'httponly' not in cookie_str:
                        security_issues.append('missing HttpOnly flag')
                
                if security_issues:
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'Medium',
                        'title': 'Insecure Cookie Configuration',
                        'description': f'Cookie "{cookie_name}" has security issues',
                        'location': self.target_url,
                        'evidence': f'Cookie "{cookie_name}": {", ".join(security_issues)}',
                        'recommendation': 'Set Secure and HttpOnly flags on sensitive cookies'
                    })
    
    def _calculate_entropy(self, token):
        """Calculate entropy of a token"""
        if not token:
            return 0
        
        import math
        from collections import Counter
        
        counter = Counter(token)
        token_length = len(token)
        entropy = 0
        
        for count in counter.values():
            p_x = count / token_length
            entropy += -p_x * math.log2(p_x)
        
        return entropy
    
    def _build_form_data(self, form):
        """Build form data for submission"""
        form_data = {}
        
        for field in form['inputs']:
            field_name = field['name']
            field_type = field.get('type', '').lower()
            field_value = field.get('value', '')
            
            if field_type in ['text', 'hidden', 'password', 'email', 'submit']:
                form_data[field_name] = field_value or 'test'
            elif field_type == 'checkbox':
                form_data[field_name] = 'on'
            elif field_type == 'radio' and field.get('checked'):
                form_data[field_name] = field_value or 'on'
        
        return form_data
    
    def _get_form_url(self, form):
        """Get full URL for form action"""
        form_action = form.get('action', '')
        return urljoin(self.target_url, form_action)