# scanners/standard/owasp_scanner.py
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from ..base_scanner import SecurityScanner

class OWASPTop10Scanner(SecurityScanner):
    """OWASP Top 10 comprehensive security scanner"""
    
    def run_scan(self):
        """Run comprehensive OWASP Top 10 security scan without progress percentage"""
        try:
            print(f"[*] Starting OWASP Top 10 scan for: {self.target_url}")
            self.update_progress("🚀 Starting security scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test 1: Information Gathering
            self.update_progress("🔍 Gathering website information...")
            website_info = self.test_info_gathering()
            
            # Test 2: XSS Scanning
            self.update_progress("🦠 Testing for XSS vulnerabilities...")
            self.test_xss()
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test 3: SQL Injection
            self.update_progress("💉 Testing for SQL injection...")
            self.test_sql_injection()
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test 4: Security Headers
            self.update_progress("📋 Checking security headers...")
            self.test_security_headers()
            
            # Test 5: Information Disclosure
            self.update_progress("📢 Checking for information disclosure...")
            self.test_info_disclosure()
            
            # Test 6: CSRF
            self.update_progress("🛡️ Checking for CSRF vulnerabilities...")
            self.test_csrf()
            
            # Finalize
            self.update_progress("📊 Generating report...")
            security_score = self.calculate_security_score()
            
            self.update_progress("✅ Scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] OWASP scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_info_gathering(self):
        """Gather basic website information"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return {'error': response}
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            links = soup.find_all('a', href=True)
            
            info = {
                'forms_count': len(forms),
                'links_count': len(links),
                'title': soup.title.string if soup.title else 'No title',
                'server': response.headers.get('Server', 'Unknown'),
                'technologies': self.detect_technologies(response)
            }
            
            print(f"[+] Found {len(forms)} forms and {len(links)} links")
            return info
            
        except Exception as e:
            print(f"[-] Info gathering error: {e}")
            return {'error': str(e)}
    
    def detect_technologies(self, response):
        """Detect web technologies"""
        technologies = []
        headers = response.headers
        content = response.text
        
        # Check for common frameworks
        if 'wp-content' in content:
            technologies.append('WordPress')
        if 'drupal' in content.lower():
            technologies.append('Drupal')
        if 'joomla' in content.lower():
            technologies.append('Joomla')
        if 'react' in content.lower() or 'react-dom' in content:
            technologies.append('React')
        if 'vue' in content.lower():
            technologies.append('Vue.js')
        if 'angular' in content.lower():
            technologies.append('Angular')
        
        # Check server
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Check programming language
        if 'php' in headers.get('X-Powered-By', '').lower():
            technologies.append('PHP')
        if 'asp.net' in headers.get('X-Powered-By', '').lower():
            technologies.append('ASP.NET')
        if 'python' in headers.get('Server', '').lower():
            technologies.append('Python')
        
        return technologies
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        xss_payloads = {
            'basic_script': '<script>alert("XSS")</script>',
            'img_onerror': '<img src=x onerror=alert("XSS")>',
            'svg_onload': '<svg onload=alert("XSS")>',
            'body_onload': '<body onload=alert("XSS")>',
            'javascript_url': 'javascript:alert("XSS")',
            'input_event': '<input onfocus=alert("XSS") autofocus>'
        }
        
        forms = self.extract_forms()
        for i, form in enumerate(forms):
            if self.check_stop_flag():
                return
            
            # Check if paused and wait
            self.check_pause_flag()
            
            self.update_progress(f"Testing XSS on form {i+1}/{len(forms)}")
            
            vulnerabilities = self.test_form_submission(form, xss_payloads, 'XSS')
            self.vulnerabilities.extend(vulnerabilities)
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        sql_payloads = {
            'basic_union': "' UNION SELECT 1,2,3--",
            'or_condition': "' OR '1'='1",
            'time_based': "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            'error_based': "' AND 1=CONVERT(int,@@version)--",
            'comment_attack': "admin'--",
            'stacked_queries': "'; DROP TABLE users--"
        }
        
        forms = self.extract_forms()
        for i, form in enumerate(forms):
            if self.check_stop_flag():
                return
            
            # Check if paused and wait
            self.check_pause_flag()
            
            self.update_progress(f"Testing SQL injection on form {i+1}/{len(forms)}")
            
            vulnerabilities = self.test_form_submission(form, sql_payloads, 'SQL Injection')
            self.vulnerabilities.extend(vulnerabilities)
    
    def test_security_headers(self):
        """Enhanced security headers testing"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            headers = response.headers
            security_headers = {
                'X-Frame-Options': {
                    'description': 'Prevents clickjacking attacks',
                    'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'description': 'Prevents MIME sniffing attacks',
                    'recommendation': 'Set X-Content-Type-Options to nosniff'
                },
                'Content-Security-Policy': {
                    'description': 'Prevents XSS and other code injection attacks',
                    'recommendation': 'Implement a strong Content Security Policy'
                },
                'Strict-Transport-Security': {
                    'description': 'Enforces HTTPS connections',
                    'recommendation': 'Set Strict-Transport-Security with appropriate max-age'
                },
                'X-XSS-Protection': {
                    'description': 'Enables browser XSS protection',
                    'recommendation': 'Set X-XSS-Protection: 1; mode=block'
                },
                'Referrer-Policy': {
                    'description': 'Controls referrer information in requests',
                    'recommendation': 'Set Referrer-Policy to strict-origin-when-cross-origin'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    self.vulnerabilities.append({
                        'category': 'Security Headers',
                        'risk_level': 'Medium',
                        'title': f'Missing Security Header: {header}',
                        'description': info['description'],
                        'location': self.target_url,
                        'evidence': f'{header} header not present in response',
                        'recommendation': info['recommendation']
                    })
                    
        except Exception as e:
            print(f"[-] Security headers error: {e}")
    
    def test_info_disclosure(self):
        """Enhanced information disclosure testing"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            text = response.text.lower()
            headers = str(response.headers).lower()
            
            # Enhanced information disclosure patterns
            disclosures = {
                'Email addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'Phone numbers': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'API keys': r'[a-zA-Z0-9]{32,}',
                'Database errors': r'mysql_fetch|postgresql.*error|ora-[0-9]|microsoft odbc',
                'Stack traces': r'stack trace|at .*\.java|at .*\.py|line \d+|file:///',
                'Server information': r'apache|nginx|iis|server:|x-powered-by'
            }
            
            for info_type, pattern in disclosures.items():
                if re.search(pattern, text, re.IGNORECASE) or re.search(pattern, headers, re.IGNORECASE):
                    risk_level = 'High' if 'key' in info_type.lower() or 'error' in info_type.lower() else 'Low'
                    self.vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': risk_level,
                        'title': f'Potential {info_type} disclosure',
                        'description': f'Sensitive {info_type.lower()} found in response',
                        'location': self.target_url,
                        'evidence': f'{info_type} pattern detected in response',
                        'recommendation': 'Review and remove sensitive information from public responses'
                    })
            
            # Check for directory listing
            test_paths = ['/images/', '/css/', '/js/', '/uploads/', '/admin/']
            for path in test_paths:
                test_url = self.target_url.rstrip('/') + path
                success, response = self.safe_request('GET', test_url)
                
                if success and response.status_code == 200:
                    if any(indicator in response.text.lower() for indicator in 
                          ['index of', 'directory listing', '<title>directory of', '<h1>directory']):
                        self.vulnerabilities.append({
                            'category': 'Information Disclosure',
                            'risk_level': 'Medium',
                            'title': 'Directory Listing Enabled',
                            'description': f'Directory listing is enabled for {path}',
                            'location': test_url,
                            'evidence': 'Directory listing exposes file structure',
                            'recommendation': 'Disable directory listing in server configuration'
                        })
                    
        except Exception as e:
            print(f"[-] Info disclosure error: {e}")
    
    def test_csrf(self):
        """Enhanced CSRF vulnerability testing"""
        forms = self.extract_forms()
        
        for form in forms:
            if form['method'] == 'post':
                # Enhanced CSRF token detection
                has_csrf = any(
                    'csrf' in input_field['name'].lower() or 
                    'token' in input_field['name'].lower() or
                    'nonce' in input_field['name'].lower() or
                    'authenticity' in input_field['name'].lower()
                    for input_field in form['inputs']
                )
                
                if not has_csrf:
                    self.vulnerabilities.append({
                        'category': 'CSRF',
                        'risk_level': 'Medium',
                        'title': 'Potential CSRF Vulnerability',
                        'description': 'Form missing CSRF protection token',
                        'location': urljoin(self.target_url, form['action']),
                        'evidence': f'No CSRF token found in form with action: {form.get("action", "")}',
                        'recommendation': 'Implement CSRF tokens for all state-changing operations'
                    })