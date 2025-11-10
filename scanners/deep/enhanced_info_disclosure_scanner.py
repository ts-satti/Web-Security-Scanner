# scanners/advanced/info_disclosure_scanner.py
import time
import re
import json
import base64
from urllib.parse import urljoin, urlparse, parse_qs
from ..base_scanner import SecurityScanner

class EnhancedInfoDisclosureScanner(SecurityScanner):
    """Advanced information disclosure scanner"""
    
    def run_scan(self):
        """Run comprehensive information disclosure scan"""
        try:
            print(f"[*] Starting Advanced Information Disclosure scan for: {self.target_url}")
            self.update_progress(10, "🚀 Initializing advanced information disclosure scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 1: Basic information disclosure
            self.update_progress(15, "📢 Scanning for basic information leaks...")
            self.test_basic_info_disclosure()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 2: Advanced data patterns
            self.update_progress(30, "🔍 Analyzing advanced data patterns...")
            self.test_advanced_data_patterns()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 3: File and directory enumeration
            self.update_progress(45, "📁 Scanning for exposed files and directories...")
            self.test_file_directory_exposure()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 4: Source code analysis
            self.update_progress(60, "💻 Analyzing source code exposure...")
            self.test_source_code_exposure()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 5: API and endpoint discovery
            self.update_progress(75, "🔌 Discovering exposed APIs and endpoints...")
            self.test_api_endpoint_exposure()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 6: Metadata and technical exposure
            self.update_progress(85, "🔧 Checking technical information leaks...")
            self.test_technical_metadata()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 7: Advanced reconnaissance
            self.update_progress(92, "🕵️ Performing advanced reconnaissance...")
            self.perform_advanced_reconnaissance()
            
            # Finalize
            self.update_progress(95, "📊 Generating comprehensive disclosure report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Advanced information disclosure scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Advanced info disclosure scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_basic_info_disclosure(self):
        """Enhanced basic information disclosure testing"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            text = response.text
            headers = str(response.headers)
            url = self.target_url
            
            # Comprehensive information disclosure patterns
            disclosures = {
                'Email addresses': {
                    'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    'risk': 'Low',
                    'description': 'Email addresses exposed in response',
                    'validation': self._validate_email
                },
                'Phone numbers': {
                    'pattern': r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b',
                    'risk': 'Low',
                    'description': 'Phone numbers exposed in response'
                },
                'API keys': {
                    'pattern': r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)[=:\s]+[\'"`]?([A-Za-z0-9]{32,})[\'"`]?',
                    'risk': 'High',
                    'description': 'API keys or secrets exposed in response'
                },
                'Database credentials': {
                    'pattern': r'(?i)(mysql|postgresql|mongodb|redis)://[^"\'\s]+',
                    'risk': 'High',
                    'description': 'Database connection strings exposed'
                },
                'AWS keys': {
                    'pattern': r'AKIA[0-9A-Z]{16}',
                    'risk': 'High',
                    'description': 'AWS access keys exposed'
                },
                'Private keys': {
                    'pattern': r'-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----',
                    'risk': 'Critical',
                    'description': 'Private cryptographic keys exposed'
                },
                'Database errors': {
                    'pattern': r'(?i)(mysql_fetch|postgresql.*error|ora-[0-9]|microsoft odbc|sqlite3\.|pdo exception|database error|sql syntax)',
                    'risk': 'Medium',
                    'description': 'Database error messages revealing system information'
                },
                'Stack traces': {
                    'pattern': r'(?i)(stack trace|at \w+\.\w+|\w+\.java:\d+|\w+\.py:\d+|line \d+|file:///|exception in|traceback|debug mode)',
                    'risk': 'Medium',
                    'description': 'Application stack traces exposing code structure'
                },
                'Server information': {
                    'pattern': r'(?i)(apache/\d|nginx/\d|iis/\d|server:|x-powered-by:|x-aspnet-version|x-runtime)',
                    'risk': 'Low',
                    'description': 'Server version information exposed in headers'
                },
                'Developer comments': {
                    'pattern': r'<!--.*(todo|fixme|hack|xxx|debug|temp|remove).*-->',
                    'risk': 'Low',
                    'description': 'Developer comments revealing internal information'
                },
                'Credit card numbers': {
                    'pattern': r'\b(?:\d[ -]*?){13,16}\b',
                    'risk': 'Critical',
                    'description': 'Credit card numbers exposed',
                    'validation': self._validate_credit_card
                },
                'Social Security Numbers': {
                    'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                    'risk': 'Critical',
                    'description': 'Social Security numbers exposed'
                },
                'JWT tokens': {
                    'pattern': r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
                    'risk': 'High',
                    'description': 'JWT tokens exposed in responses'
                },
                'Base64 encoded data': {
                    'pattern': r'[A-Za-z0-9+/]{40,}={0,2}',
                    'risk': 'Medium',
                    'description': 'Potential base64 encoded sensitive data',
                    'validation': self._validate_base64
                },
                'Internal IP addresses': {
                    'pattern': r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b',
                    'risk': 'Medium',
                    'description': 'Internal IP addresses exposed'
                },
                'API endpoints': {
                    'pattern': r'(?i)(/api/v\d+/|/graphql|/rest/|/soap/|/webservice/|/endpoint/)',
                    'risk': 'Low',
                    'description': 'API endpoints exposed in client-side code'
                }
            }
            
            for info_type, config in disclosures.items():
                if self.check_stop_flag():
                    return
                self.check_pause_flag()
                
                pattern = config['pattern']
                risk_level = config['risk']
                description = config['description']
                
                # Check response body
                body_matches = re.findall(pattern, text, re.IGNORECASE)
                # Check headers
                header_matches = re.findall(pattern, headers, re.IGNORECASE)
                
                all_matches = body_matches + header_matches
                
                # Apply validation if specified
                if 'validation' in config:
                    all_matches = [match for match in all_matches if config['validation'](match)]
                
                if all_matches:
                    sample_matches = all_matches[:3]
                    unique_matches = list(set(all_matches))
                    
                    self.vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': risk_level,
                        'title': f'{info_type} Exposure',
                        'description': f'{description} - {len(unique_matches)} unique instances found',
                        'location': self.target_url,
                        'evidence': f'Samples: {sample_matches}',
                        'recommendation': 'Remove sensitive information from public responses and implement proper error handling'
                    })
            
            # Enhanced header information analysis
            self._analyze_response_headers(response.headers)
            
            # Check for exposed cookies
            self._analyze_exposed_cookies(response)
                    
        except Exception as e:
            print(f"[-] Basic info disclosure test error: {e}")
    
    def test_advanced_data_patterns(self):
        """Test for advanced data patterns and structures"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            text = response.text
            
            # Check for JSON data exposure
            self._analyze_json_exposure(text)
            
            # Check for XML data exposure
            self._analyze_xml_exposure(text)
            
            # Check for serialized data
            self._analyze_serialized_data(text)
            
            # Check for configuration data
            self._analyze_configuration_data(text)
            
            # Check for financial data
            self._analyze_financial_data(text)
            
            # Check for personal information
            self._analyze_personal_information(text)
            
        except Exception as e:
            print(f"[-] Advanced data patterns test error: {e}")
    
    def test_file_directory_exposure(self):
        """Comprehensive file and directory exposure testing"""
        try:
            # Test directory listing
            directory_vulns = self._test_comprehensive_directory_listing()
            self.vulnerabilities.extend(directory_vulns)
            
            # Test backup files
            backup_vulns = self._test_comprehensive_backup_files()
            self.vulnerabilities.extend(backup_vulns)
            
            # Test configuration files
            config_vulns = self._test_configuration_files()
            self.vulnerabilities.extend(config_vulns)
            
            # Test log files
            log_vulns = self._test_log_files()
            self.vulnerabilities.extend(log_vulns)
            
            # Test temporary files
            temp_vulns = self._test_temporary_files()
            self.vulnerabilities.extend(temp_vulns)
            
        except Exception as e:
            print(f"[-] File directory exposure test error: {e}")
    
    def test_source_code_exposure(self):
        """Test for source code exposure"""
        try:
            # Test for exposed source files
            source_vulns = self._test_source_code_files()
            self.vulnerabilities.extend(source_vulns)
            
            # Test for version control exposure
            vcs_vulns = self._test_version_control_systems()
            self.vulnerabilities.extend(vcs_vulns)
            
            # Test for IDE files
            ide_vulns = self._test_ide_files()
            self.vulnerabilities.extend(ide_vulns)
            
            # Test for build files
            build_vulns = self._test_build_files()
            self.vulnerabilities.extend(build_vulns)
            
        except Exception as e:
            print(f"[-] Source code exposure test error: {e}")
    
    def test_api_endpoint_exposure(self):
        """Test for API and endpoint exposure"""
        try:
            # Test for API documentation
            api_doc_vulns = self._test_api_documentation()
            self.vulnerabilities.extend(api_doc_vulns)
            
            # Test for exposed endpoints
            endpoint_vulns = self._test_exposed_endpoints()
            self.vulnerabilities.extend(endpoint_vulns)
            
            # Test for admin interfaces
            admin_vulns = self._test_admin_interfaces()
            self.vulnerabilities.extend(admin_vulns)
            
        except Exception as e:
            print(f"[-] API endpoint exposure test error: {e}")
    
    def test_technical_metadata(self):
        """Test for technical metadata exposure"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            # Analyze technical information
            self._analyze_technical_information(response)
            
            # Check for framework information
            self._analyze_framework_information(response)
            
            # Check for third-party service exposure
            self._analyze_third_party_services(response)
            
        except Exception as e:
            print(f"[-] Technical metadata test error: {e}")
    
    def perform_advanced_reconnaissance(self):
        """Perform advanced reconnaissance techniques"""
        try:
            # Test for subdomain information
            self._test_subdomain_information()
            
            # Test for DNS information
            self._test_dns_information()
            
            # Test for certificate information
            self._test_certificate_information()
            
            # Test for cloud metadata
            self._test_cloud_metadata()
            
        except Exception as e:
            print(f"[-] Advanced reconnaissance error: {e}")
    
    def _validate_email(self, email):
        """Validate if string is a real email address"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern, email) is not None
    
    def _validate_credit_card(self, number):
        """Validate if string is a potential credit card number"""
        # Remove non-digits
        number = re.sub(r'\D', '', number)
        
        # Check length
        if len(number) not in [13, 14, 15, 16]:
            return False
        
        # Luhn algorithm check
        def luhn_check(num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            digits = digits_of(num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10 == 0
        
        return luhn_check(number)
    
    def _validate_base64(self, data):
        """Validate if string is legitimate base64 data"""
        try:
            # Check if it's properly padded
            padding = len(data) % 4
            if padding:
                data += '=' * (4 - padding)
            
            # Try to decode
            decoded = base64.b64decode(data)
            
            # Check if decoded data makes sense (not just random bytes)
            if len(decoded) > 10:  # Minimum reasonable length
                return True
        except:
            pass
        return False
    
    def _analyze_response_headers(self, headers):
        """Analyze response headers for information disclosure"""
        info_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Runtime', 'X-Version', 'X-Backend-Server', 'X-Server-Name',
            'X-Server-IP', 'X-Backend-IP', 'X-Application-Name'
        ]
        
        for header in info_headers:
            if header in headers:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Low',
                    'title': f'Server Information in Header: {header}',
                    'description': f'{header} header reveals server information',
                    'location': self.target_url,
                    'evidence': f'{header}: {headers[header]}',
                    'recommendation': 'Remove or obfuscate server information headers'
                })
    
    def _analyze_exposed_cookies(self, response):
        """Analyze exposed cookies for sensitive information"""
        cookies = response.cookies
        
        for cookie in cookies:
            cookie_name = cookie.name.lower()
            cookie_value = cookie.value
            
            # Check for sensitive data in cookie names
            sensitive_patterns = ['session', 'auth', 'token', 'user', 'password', 'secret']
            if any(pattern in cookie_name for pattern in sensitive_patterns):
                # Check if cookie value contains sensitive information
                if len(cookie_value) > 50:  # Suspiciously long cookie
                    self.vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': 'Medium',
                        'title': 'Potential Sensitive Data in Cookie',
                        'description': f'Cookie {cookie_name} may contain sensitive data',
                        'location': self.target_url,
                        'evidence': f'Cookie {cookie_name} has suspicious length: {len(cookie_value)}',
                        'recommendation': 'Avoid storing sensitive data in cookies; use server-side sessions'
                    })
    
    def _analyze_json_exposure(self, text):
        """Analyze JSON data exposure"""
        try:
            # Find JSON-like patterns
            json_patterns = [
                r'\{[^{}]*"[^"]*"\s*:\s*("[^"]*"|\d+|true|false|null)[^{}]*\}',
                r'\[[^\[\]]*\{[^{}]*\}[^\[\]]*\]'
            ]
            
            for pattern in json_patterns:
                matches = re.findall(pattern, text, re.DOTALL)
                for match in matches:
                    try:
                        data = json.loads(match)
                        self._check_json_sensitivity(data, match)
                    except:
                        # Try to parse as partial JSON
                        if any(keyword in match.lower() for keyword in ['password', 'secret', 'token', 'key']):
                            self.vulnerabilities.append({
                                'category': 'Information Disclosure',
                                'risk_level': 'Medium',
                                'title': 'Potential Sensitive JSON Data',
                                'description': 'JSON-like structure contains potentially sensitive fields',
                                'location': self.target_url,
                                'evidence': f'JSON fragment: {match[:100]}...',
                                'recommendation': 'Avoid exposing raw JSON data in client-side code'
                            })
        except Exception as e:
            print(f"[-] JSON analysis error: {e}")
    
    def _check_json_sensitivity(self, data, raw_json):
        """Check JSON data for sensitive information"""
        sensitive_keys = ['password', 'secret', 'token', 'key', 'auth', 'credential', 'private']
        
        def check_dict(obj, path=""):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                key_lower = str(key).lower()
                
                # Check key names
                if any(sensitive in key_lower for sensitive in sensitive_keys):
                    self.vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': 'High',
                        'title': 'Sensitive Data in JSON',
                        'description': f'JSON contains sensitive field: {current_path}',
                        'location': self.target_url,
                        'evidence': f'Field: {current_path}',
                        'recommendation': 'Remove sensitive data from client-exposed JSON'
                    })
                
                # Recursively check nested objects
                if isinstance(value, dict):
                    check_dict(value, current_path)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            check_dict(item, current_path)
        
        if isinstance(data, dict):
            check_dict(data)
    
    def _analyze_xml_exposure(self, text):
        """Analyze XML data exposure"""
        xml_pattern = r'<[^>]+>[^<]*</[^>]+>'
        matches = re.findall(xml_pattern, text)
        
        for match in matches[:5]:  # Check first 5 matches
            if any(sensitive in match.lower() for sensitive in ['password', 'secret', 'key']):
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Medium',
                    'title': 'Potential Sensitive XML Data',
                    'description': 'XML-like structure contains potentially sensitive fields',
                    'location': self.target_url,
                    'evidence': f'XML fragment: {match[:100]}...',
                    'recommendation': 'Avoid exposing raw XML data in client-side code'
                })
    
    def _analyze_serialized_data(self, text):
        """Analyze serialized data exposure"""
        serialized_patterns = {
            'PHP Serialized': r'(s:\d+:".*?";|a:\d+:\{.*?\})',
            'Java Serialized': r'\xac\xed\x00\x05',
            'Python Pickle': r'.*\.__dict__.*'
        }
        
        for data_type, pattern in serialized_patterns.items():
            matches = re.findall(pattern, text, re.DOTALL)
            if matches:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'High',
                    'title': f'Exposed {data_type} Data',
                    'description': f'Potential serialized {data_type} data exposed',
                    'location': self.target_url,
                    'evidence': f'Found {len(matches)} instances of {data_type} data',
                    'recommendation': 'Avoid exposing serialized data; use secure APIs instead'
                })
    
    def _analyze_configuration_data(self, text):
        """Analyze configuration data exposure"""
        config_patterns = {
            'Database Config': r'(host|database|username|password).*[=:].*[\'"][^\'"]+[\'"]',
            'API Config': r'(api[_-]key|app[_-]id|client[_-]secret).*[=:].*[\'"][^\'"]+[\'"]',
            'Cloud Config': r'(account[_-]sid|auth[_-]token|bucket[_-]name).*[=:].*[\'"][^\'"]+[\'"]'
        }
        
        for config_type, pattern in config_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'High',
                    'title': f'Exposed {config_type}',
                    'description': f'Configuration data exposed in client-side code',
                    'location': self.target_url,
                    'evidence': f'Sample: {matches[0][:100]}...',
                    'recommendation': 'Move configuration to server-side environment variables'
                })
    
    def _analyze_financial_data(self, text):
        """Analyze financial data exposure"""
        financial_patterns = {
            'Bank Account': r'\b\d{8,17}\b',  # Basic account number pattern
            'Routing Number': r'\b\d{9}\b',
            'SWIFT Code': r'[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?',
            'IBAN': r'[A-Z]{2}\d{2}[A-Z0-9]{1,30}'
        }
        
        for data_type, pattern in financial_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Critical',
                    'title': f'Potential {data_type} Exposure',
                    'description': f'Potential financial {data_type.lower()} exposed',
                    'location': self.target_url,
                    'evidence': f'Found {len(matches)} instances',
                    'recommendation': 'Remove all financial data from client-accessible resources'
                })
    
    def _analyze_personal_information(self, text):
        """Analyze personal information exposure"""
        personal_patterns = {
            'Date of Birth': r'\b(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/(19|20)\d{2}\b',
            'Address': r'\b\d+\s+[\w\s]+\s+(street|st|avenue|ave|road|rd|boulevard|blvd)\b',
            'Driver License': r'[A-Z][0-9]{4,8}',
            'Passport Number': r'[A-Z][0-9]{8}'
        }
        
        for data_type, pattern in personal_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'High',
                    'title': f'Potential {data_type} Exposure',
                    'description': f'Potential personal {data_type.lower()} exposed',
                    'location': self.target_url,
                    'evidence': f'Found {len(matches)} instances',
                    'recommendation': 'Remove all PII from client-accessible resources'
                })
    
    def _test_comprehensive_directory_listing(self):
        """Comprehensive directory listing testing"""
        vulnerabilities = []
        test_paths = [
            '/images/', '/css/', '/js/', '/uploads/', '/admin/', '/static/', '/assets/',
            '/files/', '/documents/', '/backups/', '/temp/', '/tmp/', '/logs/', '/data/',
            '/database/', '/config/', '/include/', '/src/', '/lib/', '/vendor/', '/node_modules/'
        ]
        
        for path in test_paths:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + path
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                content = response.text.lower()
                directory_indicators = [
                    'index of', 'directory listing', '<title>directory of', 
                    '<h1>directory', '<ul>', '<li>', 'parent directory',
                    'last modified', 'size</a>', 'name</a>'
                ]
                
                if any(indicator in content for indicator in directory_indicators):
                    vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': 'Medium',
                        'title': 'Directory Listing Enabled',
                        'description': f'Directory listing is enabled for {path}',
                        'location': test_url,
                        'evidence': 'Directory listing exposes file structure and potentially sensitive files',
                        'recommendation': 'Disable directory listing in server configuration'
                    })
        
        return vulnerabilities
    
    def _test_comprehensive_backup_files(self):
        """Comprehensive backup files testing"""
        vulnerabilities = []
        backup_files = [
            # Common backups
            '/.git/config', '/.env', '/backup.zip', '/database.sql', '/dump.sql',
            '/backup.tar', '/backup.tar.gz', '/backup.sql.gz',
            
            # Configuration backups
            '/wp-config.php.backup', '/config.bak', '/web.config.bak',
            '/.htaccess.bak', '/config.php.bak', '/settings.py.bak',
            
            # Common files
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
            
            # Temporary backups
            '/tmp/backup.sql', '/temp/database.bak',
            
            # Versioned backups
            '/v1.backup', '/old/config.php', '/previous/settings.json'
        ]
        
        for backup_file in backup_files:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + backup_file
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Medium',
                    'title': f'Exposed File: {backup_file}',
                    'description': f'Backup or configuration file accessible: {backup_file}',
                    'location': test_url,
                    'evidence': f'File {backup_file} is publicly accessible (Size: {len(response.text)} bytes)',
                    'recommendation': 'Remove or restrict access to backup and configuration files'
                })
        
        return vulnerabilities
    
    def _test_configuration_files(self):
        """Test for exposed configuration files"""
        vulnerabilities = []
        config_files = [
            '/.env', '/config.json', '/config.yml', '/config.yaml',
            '/settings.json', '/application.properties', '/pom.xml',
            '/package.json', '/composer.json', '/requirements.txt',
            '/dockerfile', '/docker-compose.yml'
        ]
        
        for config_file in config_files:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + config_file
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                content = response.text
                
                # Check for sensitive information in config files
                sensitive_patterns = ['password', 'secret', 'key', 'token', 'database']
                if any(pattern in content.lower() for pattern in sensitive_patterns):
                    vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': 'High',
                        'title': f'Exposed Configuration File: {config_file}',
                        'description': f'Configuration file with sensitive data accessible',
                        'location': test_url,
                        'evidence': f'File {config_file} contains sensitive configuration data',
                        'recommendation': 'Immediately remove configuration file and rotate exposed secrets'
                    })
        
        return vulnerabilities
    
    def _test_log_files(self):
        """Test for exposed log files"""
        vulnerabilities = []
        log_files = [
            '/logs/access.log', '/logs/error.log', '/var/log/access.log',
            '/var/log/error.log', '/tmp/error.log', '/log/app.log',
            '/debug.log', '/error_log', '/access_log'
        ]
        
        for log_file in log_files:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + log_file
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'High',
                    'title': f'Exposed Log File: {log_file}',
                    'description': f'Application log file accessible',
                    'location': test_url,
                    'evidence': f'Log file {log_file} is publicly accessible',
                    'recommendation': 'Restrict access to log files and store them in secure locations'
                })
        
        return vulnerabilities
    
    def _test_temporary_files(self):
        """Test for exposed temporary files"""
        vulnerabilities = []
        temp_files = [
            '/tmp/upload.tmp', '/temp/session.dat', '/cache/temp.db',
            '/uploads/temp.file', '/var/tmp/backup.tmp'
        ]
        
        for temp_file in temp_files:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + temp_file
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Medium',
                    'title': f'Exposed Temporary File: {temp_file}',
                    'description': f'Temporary file accessible',
                    'location': test_url,
                    'evidence': f'Temporary file {temp_file} is publicly accessible',
                    'recommendation': 'Implement proper temporary file cleanup and access controls'
                })
        
        return vulnerabilities
    
    def _test_source_code_files(self):
        """Test for exposed source code files"""
        vulnerabilities = []
        source_files = [
            '/.php', '/.py', '/.java', '/.class', '/.rb', '/.go',
            '/index.php', '/app.py', '/main.java', '/server.js',
            '/.env.example', '/config.example.json'
        ]
        
        for source_file in source_files:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + source_file
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'High',
                    'title': f'Exposed Source Code: {source_file}',
                    'description': f'Source code file accessible',
                    'location': test_url,
                    'evidence': f'Source file {source_file} is publicly accessible',
                    'recommendation': 'Remove source code files from web-accessible directories'
                })
        
        return vulnerabilities
    
    def _test_version_control_systems(self):
        """Test for version control system exposure"""
        vulnerabilities = []
        vcs_files = [
            '/.git/HEAD', '/.git/config', '/.git/logs/HEAD',
            '/.svn/entries', '/.hg/store/00manifest.i',
            '/.gitignore', '/.svnignore'
        ]
        
        for vcs_file in vcs_files:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + vcs_file
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'High',
                    'title': f'Exposed Version Control: {vcs_file}',
                    'description': f'Version control system file accessible',
                    'location': test_url,
                    'evidence': f'VCS file {vcs_file} is publicly accessible',
                    'recommendation': 'Remove version control directories from production servers'
                })
        
        return vulnerabilities
    
    def _test_ide_files(self):
        """Test for IDE configuration files"""
        vulnerabilities = []
        ide_files = [
            '/.idea/workspace.xml', '/.vscode/settings.json',
            '/.project', '/.classpath', '/.settings/org.eclipse.wst.common.project.facet.core.xml'
        ]
        
        for ide_file in ide_files:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + ide_file
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Medium',
                    'title': f'Exposed IDE Configuration: {ide_file}',
                    'description': f'IDE configuration file accessible',
                    'location': test_url,
                    'evidence': f'IDE file {ide_file} is publicly accessible',
                    'recommendation': 'Remove IDE configuration files from production servers'
                })
        
        return vulnerabilities
    
    def _test_build_files(self):
        """Test for build system files"""
        vulnerabilities = []
        build_files = [
            '/pom.xml', '/build.gradle', '/package.json',
            '/composer.json', '/requirements.txt', '/Makefile'
        ]
        
        for build_file in build_files:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + build_file
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Low',
                    'title': f'Exposed Build File: {build_file}',
                    'description': f'Build system file accessible',
                    'location': test_url,
                    'evidence': f'Build file {build_file} is publicly accessible',
                    'recommendation': 'Remove build system files from production servers'
                })
        
        return vulnerabilities
    
    def _test_api_documentation(self):
        """Test for exposed API documentation"""
        vulnerabilities = []
        api_docs = [
            '/api-docs', '/swagger-ui.html', '/swagger.json',
            '/openapi.json', '/api/v1/docs', '/graphql',
            '/redoc', '/api/help', '/rest/docs'
        ]
        
        for api_doc in api_docs:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + api_doc
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Low',
                    'title': f'Exposed API Documentation: {api_doc}',
                    'description': f'API documentation accessible',
                    'location': test_url,
                    'evidence': f'API documentation at {api_doc} is publicly accessible',
                    'recommendation': 'Restrict API documentation to authorized users only'
                })
        
        return vulnerabilities
    
    def _test_exposed_endpoints(self):
        """Test for exposed API endpoints"""
        vulnerabilities = []
        endpoints = [
            '/api/v1/users', '/api/admin', '/api/config',
            '/graphql', '/rest/users', '/soap/api',
            '/api/database', '/api/secrets'
        ]
        
        for endpoint in endpoints:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + endpoint
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                # Check if endpoint returns sensitive data
                content = response.text.lower()
                if any(keyword in content for keyword in ['password', 'secret', 'key', 'token']):
                    vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': 'High',
                        'title': f'Exposed API Endpoint: {endpoint}',
                        'description': f'API endpoint returns sensitive data',
                        'location': test_url,
                        'evidence': f'Endpoint {endpoint} returns sensitive information',
                        'recommendation': 'Implement proper authentication and data filtering for API endpoints'
                    })
        
        return vulnerabilities
    
    def _test_admin_interfaces(self):
        """Test for exposed admin interfaces"""
        vulnerabilities = []
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/manager',
            '/console', '/webadmin', '/cpanel', '/phpmyadmin'
        ]
        
        for admin_path in admin_paths:
            if self.check_stop_flag():
                return vulnerabilities
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + admin_path
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Medium',
                    'title': f'Exposed Admin Interface: {admin_path}',
                    'description': f'Administrative interface accessible',
                    'location': test_url,
                    'evidence': f'Admin interface at {admin_path} is publicly accessible',
                    'recommendation': 'Restrict admin interfaces to authorized IP ranges and use strong authentication'
                })
        
        return vulnerabilities
    
    def _analyze_technical_information(self, response):
        """Analyze technical information exposure"""
        # Check for framework-specific information
        frameworks = {
            'WordPress': ['wp-json', 'wp-includes', 'wp-content'],
            'Drupal': ['sites/default/files'],
            'Joomla': ['administrator/components'],
            'Laravel': ['storage/framework', 'vendor/laravel'],
            'Django': ['admin/login', 'static/admin'],
            'Rails': ['assets/rails', 'javascripts/rails']
        }
        
        text = response.text
        headers = str(response.headers)
        
        for framework, indicators in frameworks.items():
            if any(indicator in text or indicator in headers for indicator in indicators):
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Low',
                    'title': f'Framework Detection: {framework}',
                    'description': f'{framework} framework detected',
                    'location': self.target_url,
                    'evidence': f'{framework} indicators found in response',
                    'recommendation': 'Consider obfuscating framework fingerprints for security'
                })
    
    def _analyze_framework_information(self, response):
        """Analyze framework-specific information leaks"""
        text = response.text
        
        # Check for WordPress information
        if 'wp-content' in text or 'wp-includes' in text:
            # Look for WordPress version
            version_pattern = r'wp-embed\.js\?ver=([0-9.]+)'
            version_match = re.search(version_pattern, text)
            if version_match:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Low',
                    'title': 'WordPress Version Exposure',
                    'description': 'WordPress version exposed in client-side code',
                    'location': self.target_url,
                    'evidence': f'WordPress version {version_match.group(1)} detected',
                    'recommendation': 'Hide WordPress version information from public view'
                })
    
    def _analyze_third_party_services(self, response):
        """Analyze third-party service exposure"""
        text = response.text
        
        third_party_services = {
            'Google Analytics': ['google-analytics.com', 'ga.js', 'analytics.js'],
            'Facebook': ['connect.facebook.net', 'fbcdn.net'],
            'Twitter': ['platform.twitter.com', 'twitter-widgets.js'],
            'Cloudflare': ['cloudflare.com', 'cf-cdn.net'],
            'AWS': ['amazonaws.com', 's3.amazonaws.com'],
            'Google Cloud': ['googleapis.com', 'gstatic.com']
        }
        
        for service, domains in third_party_services.items():
            if any(domain in text for domain in domains):
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Info',
                    'title': f'Third-Party Service: {service}',
                    'description': f'{service} integration detected',
                    'location': self.target_url,
                    'evidence': f'{service} domains found in response',
                    'recommendation': 'Monitor third-party services for security updates'
                })
    
    def _test_subdomain_information(self):
        """Test for subdomain information exposure"""
        # This would typically involve DNS enumeration
        # For now, we'll check common subdomains
        common_subdomains = [
            'www', 'api', 'admin', 'test', 'staging', 'dev',
            'mail', 'ftp', 'cpanel', 'webmail', 'blog'
        ]
        
        domain = urlparse(self.target_url).netloc
        
        for subdomain in common_subdomains:
            if self.check_stop_flag():
                return
            self.check_pause_flag()
            
            test_url = f"https://{subdomain}.{domain}"
            success, response = self.safe_request('GET', test_url)
            
            if success:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Info',
                    'title': f'Subdomain Discovered: {subdomain}',
                    'description': f'Subdomain {subdomain}.{domain} is accessible',
                    'location': test_url,
                    'evidence': f'Subdomain responds with status {response.status_code}',
                    'recommendation': 'Ensure all subdomains have proper security controls'
                })
    
    def _test_dns_information(self):
        """Test for DNS information exposure"""
        # This would involve DNS record analysis
        # Placeholder for DNS information checks
        pass
    
    def _test_certificate_information(self):
        """Test for SSL certificate information exposure"""
        # This would involve SSL certificate analysis
        # Placeholder for certificate checks
        pass
    
    def _test_cloud_metadata(self):
        """Test for cloud metadata exposure"""
        # Check for common cloud metadata endpoints
        metadata_endpoints = [
            '/latest/meta-data/',
            '/metadata/instance',
            '/computeMetadata/v1/'
        ]
        
        for endpoint in metadata_endpoints:
            if self.check_stop_flag():
                return
            self.check_pause_flag()
            
            test_url = self.target_url.rstrip('/') + endpoint
            success, response = self.safe_request('GET', test_url)
            
            if success and response.status_code == 200:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Critical',
                    'title': 'Cloud Metadata Endpoint Exposed',
                    'description': 'Cloud instance metadata endpoint is publicly accessible',
                    'location': test_url,
                    'evidence': f'Cloud metadata endpoint {endpoint} returns data',
                    'recommendation': 'Immediately restrict access to cloud metadata endpoints'
                })