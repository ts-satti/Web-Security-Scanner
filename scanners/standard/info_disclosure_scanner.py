# scanners/standard/info_disclosure_scanner.py
import time
import re
from urllib.parse import urljoin
from ..base_scanner import SecurityScanner

class InfoDisclosureScanner(SecurityScanner):
    """Standard information disclosure scanner"""
    
    def run_scan(self):
        """Run focused information disclosure scan"""
        try:
            print(f"[*] Starting Information Disclosure scan for: {self.target_url}")
            self.update_progress(10, "🚀 Starting information disclosure scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test information disclosure
            self.update_progress(50, "📢 Checking for information disclosure...")
            self.test_info_disclosure()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating information disclosure report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Information disclosure scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Info disclosure scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_info_disclosure(self):
        """Enhanced information disclosure testing"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            text = response.text
            headers = str(response.headers)
            
            # Enhanced information disclosure patterns
            disclosures = {
                'Email addresses': {
                    'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    'risk': 'Low',
                    'description': 'Email addresses exposed in response'
                },
                'Phone numbers': {
                    'pattern': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                    'risk': 'Low',
                    'description': 'Phone numbers exposed in response'
                },
                'API keys': {
                    'pattern': r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)[=:\s]+[\'"`]?([A-Za-z0-9]{32,})[\'"`]?',
                    'risk': 'High',
                    'description': 'API keys or secrets exposed in response'
                },
                'Database credentials': {
                    'pattern': r'(?i)(mysql|postgresql|mongodb)://[^"\'\s]+',
                    'risk': 'High',
                    'description': 'Database connection strings exposed'
                },
                'AWS keys': {
                    'pattern': r'AKIA[0-9A-Z]{16}',
                    'risk': 'High',
                    'description': 'AWS access keys exposed'
                },
                'Private keys': {
                    'pattern': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                    'risk': 'Critical',
                    'description': 'Private cryptographic keys exposed'
                },
                'Database errors': {
                    'pattern': r'mysql_fetch|postgresql.*error|ora-[0-9]|microsoft odbc|sqlite3\.|pdo exception',
                    'risk': 'Medium',
                    'description': 'Database error messages revealing system information'
                },
                'Stack traces': {
                    'pattern': r'stack trace|at .*\.java|at .*\.py|line \d+|file:///|exception in|traceback',
                    'risk': 'Medium',
                    'description': 'Application stack traces exposing code structure'
                },
                'Server information': {
                    'pattern': r'apache/\d|nginx/\d|iis/\d|server:|x-powered-by:|x-aspnet-version',
                    'risk': 'Low',
                    'description': 'Server version information exposed in headers'
                },
                'Developer comments': {
                    'pattern': r'<!--.*(todo|fixme|hack|xxx|debug).*-->',
                    'risk': 'Low',
                    'description': 'Developer comments revealing internal information'
                }
            }
            
            found_vulnerabilities = False
            
            for info_type, config in disclosures.items():
                if self.check_stop_flag():
                    return
                # Check if paused and wait
                self.check_pause_flag()
                
                pattern = config['pattern']
                risk_level = config['risk']
                description = config['description']
                
                # Check response body
                body_matches = re.findall(pattern, text, re.IGNORECASE)
                # Check headers
                header_matches = re.findall(pattern, headers, re.IGNORECASE)
                
                all_matches = body_matches + header_matches
                
                if all_matches:
                    sample_matches = all_matches[:3]  # Show first 3 matches as evidence
                    found_vulnerabilities = True
                    
                    self.vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': risk_level,
                        'title': f'{info_type} Exposure',
                        'description': description,
                        'location': self.target_url,
                        'evidence': f'Found {len(all_matches)} instances. Samples: {sample_matches}',
                        'recommendation': 'Remove sensitive information from public responses and implement proper error handling'
                    })
            
            # Check for directory listing
            directory_vuln = self.test_directory_listing()
            if directory_vuln:
                found_vulnerabilities = True
                self.vulnerabilities.append(directory_vuln)
            
            # Check for backup files
            backup_vulns = self.test_backup_files()
            self.vulnerabilities.extend(backup_vulns)
            if backup_vulns:
                found_vulnerabilities = True
            
            # If no information disclosure found, add informational finding
            if not found_vulnerabilities:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Info',
                    'title': 'No Significant Information Disclosure Found',
                    'description': 'No obvious sensitive information exposure detected',
                    'location': self.target_url,
                    'evidence': 'Standard scan completed without finding exposed sensitive data',
                    'recommendation': 'Continue regular security assessments and monitor for information leaks'
                })
                    
        except Exception as e:
            print(f"[-] Info disclosure test error: {e}")
    
    def test_directory_listing(self):
        """Test for directory listing vulnerabilities"""
        try:
            test_paths = ['/images/', '/css/', '/js/', '/uploads/', '/admin/', '/static/', '/assets/']
            for path in test_paths:
                if self.check_stop_flag():
                    return None
                # Check if paused and wait
                self.check_pause_flag()
                
                test_url = self.target_url.rstrip('/') + path
                success, response = self.safe_request('GET', test_url)
                
                if success and response.status_code == 200:
                    content = response.text.lower()
                    # Enhanced directory listing indicators
                    if any(indicator in content for indicator in 
                          ['index of', 'directory listing', '<title>directory of', '<h1>directory', '<ul>', '<li>']):
                        return {
                            'category': 'Information Disclosure',
                            'risk_level': 'Medium',
                            'title': 'Directory Listing Enabled',
                            'description': f'Directory listing is enabled for {path}',
                            'location': test_url,
                            'evidence': 'Directory listing exposes file structure and potentially sensitive files',
                            'recommendation': 'Disable directory listing in server configuration'
                        }
        except Exception as e:
            print(f"[-] Directory listing test error: {e}")
        
        return None
    
    def test_backup_files(self):
        """Test for exposed backup files"""
        try:
            backup_files = [
                '/.git/config', '/.env', '/backup.zip', '/database.sql',
                '/wp-config.php.backup', '/config.bak', '/web.config.bak',
                '/.htaccess.bak', '/robots.txt', '/sitemap.xml'
            ]
            
            vulnerabilities = []
            for backup_file in backup_files:
                if self.check_stop_flag():
                    return vulnerabilities
                # Check if paused and wait
                self.check_pause_flag()
                
                test_url = self.target_url.rstrip('/') + backup_file
                success, response = self.safe_request('GET', test_url)
                
                if success and response.status_code == 200:
                    vulnerabilities.append({
                        'category': 'Information Disclosure',
                        'risk_level': 'Medium',
                        'title': f'Exposed Backup File: {backup_file}',
                        'description': f'Backup or configuration file accessible: {backup_file}',
                        'location': test_url,
                        'evidence': f'File {backup_file} is publicly accessible',
                        'recommendation': 'Remove or restrict access to backup and configuration files'
                    })
            
            return vulnerabilities
        except Exception as e:
            print(f"[-] Backup files test error: {e}")
            return []