# scanners/deep/fuzz_scanner.py
import time
import random
import string
from urllib.parse import urljoin, quote, unquote
import re
from ..base_scanner import SecurityScanner

class FuzzTestingScanner(SecurityScanner):
    """Security-focused input validation scanner"""
    
    def __init__(self, target_url, scan_id, config=None):  # ✅ Added scan_id parameter
        super().__init__(target_url, scan_id, config)      # ✅ Pass to parent
        self.payload_categories = {}
        self.intelligent_payloads = []
        self.tested_endpoints = set()
        self.baseline_responses = {}

    def run_scan(self):
        """Run security validation scan"""
        try:
            print(f"[*] Starting security validation scan for: {self.target_url}")
            self.update_progress(10, "🔒 Starting security validation...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Generate security test patterns
            self.generate_security_patterns()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(30, "📝 Testing form inputs...")
            self.test_forms()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(50, "🔗 Testing URL parameters...")
            self.test_url_params()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(70, "📎 Testing file handling...")
            self.test_file_handling()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(85, "🔌 Testing API endpoints...")
            self.test_api_endpoints()
            
            # Finalize
            self.update_progress(95, "📊 Generating security report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, f"✅ Security validation completed! Tested {len(self.tested_endpoints)} endpoints")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Security validation error: {e}")
            return self._build_results('error', error_message=str(e))

    def generate_security_patterns(self):
        """Generate enhanced security test patterns (antivirus-safe)"""
        
        # Enhanced SQL Injection patterns with variations
        self.payload_categories['sql_patterns'] = [
            "test' OR 'test'='test",
            "admin' AND '1'='1", 
            "value' UNION SELECT 'test",
            "input' WHERE 'a'='a",
            "data' LIKE '%test%",
            "' OR 1=1--",
            "' UNION SELECT null--",
            "' AND SLEEP(1)--",
            "'; DROP TABLE test--",
            "' OR 'a'='a'--",
        ]
        
        # Enhanced XSS patterns with context variations
        self.payload_categories['xss_patterns'] = [
            "<test>security_test</test>",
            "<img src='test_image'>",
            "<div style='color:red'>test</div>",
            "javascript:void(0)",
            "onload='console.log()'",
            "\"><script>alert('test')</script>",
            "onmouseover=alert('test')",
            "javascript:alert('test')",
            "<script>console.log('test')</script>",
            "<svg onload=alert('test')>",
        ]
        
        # Enhanced Path traversal patterns with encoding variations
        self.payload_categories['path_patterns'] = [
            "../../../test_file.txt",
            "..\\..\\test_document.pdf",
            "%2e%2e%2ftemp%2ftest",
            "....//....//test_folder//test",
            "..\\..\\..\\Users\\Public\\test.txt",
            "../var/www/test",
            "..\\..\\ProgramData\\test",
            "~/.config/test",
            "C:\\Users\\Public\\test.txt",
            "/home/user/test/document.pdf",
            "..%2f..%2f..%2ftest",
            "..%c0%af..%c0%af..%c0%aftest",  # Unicode encoding
        ]
        
        # Enhanced Input validation patterns
        self.payload_categories['validation_patterns'] = [
            "{{7*7}}",
            "${test}",
            "#{test}",
            "%s%s%s",
            "A" * 100,
            "test\r\ntest",
            "test%00test",
            "test<script>test</script>",
            "{7*7}",
            "${7*7}",
            "#{7*7}",
        ]
        
        # Enhanced Special character patterns
        self.payload_categories['special_chars'] = [
            "!@#$%^&*()",
            "<>?:\"{}|",
            "[];',./",
            "`~\\_+-=",
            "🚀🤖⚡",
            "\x00\x01\x02\x03",  # Control characters
            "%0a%0d%00",  # Encoded newlines and null
        ]
        
        # Enhanced Command patterns with context variations
        self.payload_categories['command_patterns'] = [
            "echo test",
            "dir test",
            "ls -l",
            "whoami",
            "pwd",
            "| whoami",
            "; whoami",
            "`whoami`",
            "$(whoami)",
            "&& whoami",
        ]
        
        # Add encoded variations
        self._generate_encoded_variations()
        
        # Combine all patterns
        self.intelligent_payloads = []
        for category, patterns in self.payload_categories.items():
            self.intelligent_payloads.extend([(category, pattern) for pattern in patterns])

    def _generate_encoded_variations(self):
        """Generate URL encoded and other variations of payloads"""
        encoded_patterns = {}
        
        for category, patterns in self.payload_categories.items():
            encoded_patterns[category] = patterns.copy()
            for pattern in patterns:
                # URL encode
                encoded_patterns[category].append(quote(pattern))
                # Double URL encode
                encoded_patterns[category].append(quote(quote(pattern)))
                # HTML encode basic
                html_encoded = pattern.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
                encoded_patterns[category].append(html_encoded)
        
        # Update categories with encoded variations
        for category, patterns in encoded_patterns.items():
            self.payload_categories[category].extend(patterns)

    def test_forms(self):
        """Test form inputs with security patterns"""
        forms = self.extract_forms()
        
        for form in forms:
            if self.check_stop_flag():
                return
                
            form_url = self._get_form_url(form)
            self.tested_endpoints.add(form_url)
            
            # Get baseline response first
            baseline_response = self._get_baseline_response(form, form_url)
            
            # Test patterns systematically by category
            for category in self.payload_categories.keys():
                if self.check_stop_flag():
                    return
                    
                # Get 3-5 patterns from each category
                category_patterns = [p for cat, p in self.intelligent_payloads if cat == category]
                test_patterns = random.sample(category_patterns, min(4, len(category_patterns)))
                
                for pattern in test_patterns:
                    if self.check_stop_flag():
                        return
                        
                    self.check_pause_flag()
                    
                    form_method = form.get('method', 'get').lower()
                    data = self._prepare_form_data(form, pattern)
                    
                    try:
                        if form_method == 'post':
                            success, response = self.safe_request('POST', form_url, data=data)
                        else:
                            success, response = self.safe_request('GET', form_url, params=data)
                        
                        if success:
                            self._analyze_security_response(response, category, pattern, form_url, 'form', baseline_response)
                        
                    except Exception:
                        continue
                    
                    time.sleep(0.1)

    def test_url_params(self):
        """Test URL parameters with security patterns"""
        urls = self.extract_urls()
        
        for url in urls[:10]:
            if self.check_stop_flag():
                return
                
            self.tested_endpoints.add(url)
            
            # Get baseline response
            success, baseline_response = self.safe_request('GET', url)
            if not success:
                baseline_response = None
            
            # Test by category
            for category in self.payload_categories.keys():
                if self.check_stop_flag():
                    return
                    
                category_patterns = [p for cat, p in self.intelligent_payloads if cat == category]
                test_patterns = random.sample(category_patterns, min(3, len(category_patterns)))
                
                for pattern in test_patterns:
                    if self.check_stop_flag():
                        return
                        
                    self.check_pause_flag()
                    
                    # Test with pattern as parameter value
                    test_url = f"{url}?security_test={quote(pattern)}"
                    
                    success, response = self.safe_request('GET', test_url)
                    if success:
                        self._analyze_security_response(response, category, pattern, test_url, 'url_param', baseline_response)

    def test_file_handling(self):
        """Test file upload handling (safe patterns only)"""
        forms = self.extract_forms()
        
        for form in forms:
            if self.check_stop_flag():
                return
                
            # Check if form has file upload
            has_file_upload = any(input_field.get('type') == 'file' for input_field in form['inputs'])
            
            if has_file_upload:
                form_url = self._get_form_url(form)
                test_files = self._generate_safe_test_files()
                
                for filename, content in test_files:
                    if self.check_stop_flag():
                        return
                        
                    files = {'file': (filename, content, 'text/plain')}
                    data = self._prepare_form_data(form, 'test_value', skip_file_fields=True)
                    
                    success, response = self.safe_request('POST', form_url, data=data, files=files)
                    
                    if success:
                        self._analyze_file_response(response, filename, form_url)

    def test_api_endpoints(self):
        """Test API endpoints with JSON patterns"""
        api_patterns = ['/api/', '/v1/', '/v2/', '/rest/']
        urls = self.extract_urls()
        
        api_urls = [url for url in urls if any(pattern in url for pattern in api_patterns)]
        
        for api_url in api_urls[:8]:
            if self.check_stop_flag():
                return
                
            self.tested_endpoints.add(api_url)
            
            # Test JSON patterns by category
            for category in ['sql_patterns', 'xss_patterns', 'validation_patterns']:
                if self.check_stop_flag():
                    return
                    
                category_patterns = [p for cat, p in self.intelligent_payloads if cat == category]
                test_patterns = random.sample(category_patterns, min(3, len(category_patterns)))
                
                for pattern in test_patterns:
                    if self.check_stop_flag():
                        return
                        
                    json_payload = {'input': pattern, 'test': pattern, 'data': pattern}
                    success, response = self.safe_request('POST', api_url, json=json_payload)
                    if success:
                        self._analyze_security_response(response, 'json_pattern', str(pattern), api_url, 'api')

    def _get_baseline_response(self, form, form_url):
        """Get baseline response for differential analysis"""
        try:
            form_method = form.get('method', 'get').lower()
            baseline_data = self._prepare_form_data(form, 'test')
            
            if form_method == 'post':
                success, response = self.safe_request('POST', form_url, data=baseline_data)
            else:
                success, response = self.safe_request('GET', form_url, params=baseline_data)
            
            return response if success else None
        except Exception:
            return None

    def _prepare_form_data(self, form, pattern, skip_file_fields=False):
        """Prepare form data with security pattern"""
        data = {}
        for input_field in form['inputs']:
            field_name = input_field['name']
            field_type = input_field.get('type', 'text')
            
            if skip_file_fields and field_type == 'file':
                continue
                
            if field_type in ['text', 'search', 'hidden', 'textarea', 'email', 'password', 'url']:
                data[field_name] = pattern
            elif field_type in ['checkbox', 'radio']:
                data[field_name] = 'on'
            elif field_type == 'number':
                data[field_name] = '123'
            elif field_type == 'date':
                data[field_name] = '2024-01-01'
            else:
                data[field_name] = input_field.get('value', 'test')
        
        return data

    def _analyze_security_response(self, response, category, pattern, location, context, baseline_response=None):
        """Enhanced analysis with differential detection"""
        response_text = response.text.lower() if response.text else ''
        pattern_lower = pattern.lower()
        
        # SQL Injection detection
        if category == 'sql_patterns':
            self._detect_sql_injection(response, pattern, location, context)
        
        # XSS detection
        elif category == 'xss_patterns':
            self._detect_xss(response, pattern, location, context)
        
        # Path traversal detection
        elif category == 'path_patterns':
            self._detect_path_traversal(response, pattern, location, context)
        
        # Command injection detection
        elif category == 'command_patterns':
            self._detect_command_injection(response, pattern, location, context)
        
        # Template injection detection
        elif category == 'validation_patterns' and any(tag in pattern for tag in ['{{', '${', '#{']):
            self._detect_template_injection(response, pattern, location, context)
        
        # Generic error-based detection
        if response.status_code >= 500:
            self.vulnerabilities.append({
                'category': 'Input Validation',
                'risk_level': 'Medium',
                'title': f'Server Error with {category}',
                'description': f'Server returned error 500 with security pattern',
                'location': location,
                'evidence': f'Pattern: {pattern[:50]}... (Status: {response.status_code})',
                'recommendation': 'Implement proper input validation and error handling'
            })
        
        # Differential analysis
        if baseline_response and baseline_response.text:
            self._perform_differential_analysis(response, baseline_response, pattern, location, context)

    def _detect_sql_injection(self, response, pattern, location, context):
        """Detect SQL injection vulnerabilities"""
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
            'microsoft odbc', 'odbc driver', 'pdoexception',
            'sqlite3', 'database error', 'syntax error',
            'unclosed quotation', 'undefined column'
        ]
        
        response_text = response.text.lower()
        
        if any(error in response_text for error in sql_errors):
            self.vulnerabilities.append({
                'category': 'SQL Injection',
                'risk_level': 'High',
                'title': 'Potential SQL Injection Vulnerability',
                'description': 'Application may be vulnerable to SQL injection attacks',
                'location': location,
                'evidence': f'Database error detected with pattern: {pattern[:50]}...',
                'recommendation': 'Use parameterized queries and input validation'
            })

    def _detect_xss(self, response, pattern, location, context):
        """Detect XSS vulnerabilities"""
        response_text = response.text
        decoded_pattern = unquote(pattern)
        
        # Check for unencoded reflection in HTML context
        if decoded_pattern in response_text:
            # Check if reflected in dangerous contexts
            dangerous_contexts = [
                f'<script>{decoded_pattern}</script>' in response_text,
                f'onload="{decoded_pattern}"' in response_text,
                f'javascript:{decoded_pattern}' in response_text,
                f'<img src="{decoded_pattern}">' in response_text,
            ]
            
            if any(dangerous_contexts):
                self.vulnerabilities.append({
                    'category': 'Cross-Site Scripting',
                    'risk_level': 'High',
                    'title': 'Potential XSS Vulnerability',
                    'description': 'Input reflected without proper encoding in dangerous context',
                    'location': location,
                    'evidence': f'Pattern reflected dangerously: {decoded_pattern[:50]}...',
                    'recommendation': 'Implement proper output encoding and Content Security Policy'
                })

    def _detect_path_traversal(self, response, pattern, location, context):
        """Detect path traversal vulnerabilities"""
        # Check for file content indicators
        file_indicators = [
            'test file for security validation',
            'root:',
            'etc/passwd',
            'windows/system32',
            'this is a test file'
        ]
        
        response_text = response.text.lower()
        
        if any(indicator in response_text for indicator in file_indicators):
            self.vulnerabilities.append({
                'category': 'Path Traversal',
                'risk_level': 'High',
                'title': 'Potential Path Traversal Vulnerability',
                'description': 'Application may allow directory traversal',
                'location': location,
                'evidence': f'File content detected with pattern: {pattern[:50]}...',
                'recommendation': 'Validate and sanitize file paths'
            })

    def _detect_command_injection(self, response, pattern, location, context):
        """Detect command injection vulnerabilities"""
        # Check for command output indicators
        command_indicators = [
            'test',  # From our safe echo command
            'whoami', 'root', 'administrator',
            'c:\\', '/home/', '/var/',
            'total', 'bytes free'  # From dir/ls commands
        ]
        
        response_text = response.text.lower()
        
        if any(indicator in response_text for indicator in command_indicators):
            self.vulnerabilities.append({
                'category': 'Command Injection',
                'risk_level': 'High',
                'title': 'Potential Command Injection Vulnerability',
                'description': 'Application may execute system commands',
                'location': location,
                'evidence': f'Command output detected with pattern: {pattern[:50]}...',
                'recommendation': 'Use safe APIs and validate all inputs'
            })

    def _detect_template_injection(self, response, pattern, location, context):
        """Detect template injection vulnerabilities"""
        if '49' in response.text:  # 7*7 result
            self.vulnerabilities.append({
                'category': 'Template Injection',
                'risk_level': 'Medium',
                'title': 'Potential Template Injection Vulnerability',
                'description': 'Application may evaluate template expressions',
                'location': location,
                'evidence': f'Template expression evaluated: {pattern[:50]}...',
                'recommendation': 'Sanitize template inputs and use sandboxing'
            })

    def _perform_differential_analysis(self, response, baseline_response, pattern, location, context):
        """Compare attack response with baseline"""
        baseline_text = baseline_response.text.lower() if baseline_response.text else ''
        attack_text = response.text.lower() if response.text else ''
        
        # Check for significant content length changes
        baseline_len = len(baseline_text)
        attack_len = len(attack_text)
        
        if baseline_len > 0 and abs(baseline_len - attack_len) > baseline_len * 0.3:
            self.vulnerabilities.append({
                'category': 'Input Validation',
                'risk_level': 'Low',
                'title': 'Significant Content Change Detected',
                'description': 'Attack payload caused significant response size change',
                'location': location,
                'evidence': f'Size change: {baseline_len} -> {attack_len} with pattern: {pattern[:30]}...',
                'recommendation': 'Review input validation logic'
            })
        
        # Check for error state changes
        baseline_ok = 200 <= baseline_response.status_code < 300
        attack_ok = 200 <= response.status_code < 300
        
        if baseline_ok and not attack_ok:
            self.vulnerabilities.append({
                'category': 'Input Validation',
                'risk_level': 'Medium',
                'title': 'Error State Induced by Payload',
                'description': 'Attack payload caused application error',
                'location': location,
                'evidence': f'Status change: {baseline_response.status_code} -> {response.status_code}',
                'recommendation': 'Improve error handling and input validation'
            })

    def _analyze_file_response(self, response, filename, location):
        """Enhanced file upload response analysis"""
        if response.status_code == 200:
            # Check if file content might be accessible
            if any(ext in filename.lower() for ext in ['.php', '.jsp', '.asp', '.aspx']):
                risk_level = 'High'
                description = 'Potential executable file upload accepted'
            else:
                risk_level = 'Low'
                description = 'Test file upload was accepted'
            
            self.vulnerabilities.append({
                'category': 'File Upload',
                'risk_level': risk_level,
                'title': f'File Upload Accepted: {filename}',
                'description': description,
                'location': location,
                'evidence': f'Uploaded file: {filename} (Status: {response.status_code})',
                'recommendation': 'Implement strict file type validation and scanning'
            })

    def _generate_safe_test_files(self):
        """Generate enhanced safe test files"""
        return [
            ('test.txt', 'This is a test file for security validation.'),
            ('test.html', '<html><body>Test content</body></html>'),
            ('test.json', '{"test": "security_validation_data"}'),
            ('test.xml', '<root><test>security_validation</test></root>'),
            ('test.csv', 'header1,header2,header3\ntest1,test2,test3'),
            ('document.pdf', '%PDF-1.4 test content'),
            ('image.jpg', 'JPEG test content'),
            ('test.php.txt', '<?php echo "test"; ?>'),  # Disguised PHP
            ('test.aspx.txt', '<%@ Page Language="C#" %>'),  # Disguised ASPX
            ('test.jsp.txt', '<%@ page language="java" %>'),  # Disguised JSP
        ]

    def _get_form_url(self, form):
        """Get full URL for form action"""
        form_action = form.get('action', '')
        return urljoin(self.target_url, form_action)