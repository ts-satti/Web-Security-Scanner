# scanners/standard/headers_scanner.py
import time
from ..base_scanner import SecurityScanner

class HeadersScanner(SecurityScanner):
    """Standard security headers scanner"""
    
    def run_scan(self):
        """Run focused security headers scan"""
        try:
            print(f"[*] Starting Security Headers scan for: {self.target_url}")
            self.update_progress(10, "🚀 Starting security headers scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test security headers
            self.update_progress(50, "📋 Checking security headers...")
            self.test_security_headers()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating security headers report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Security headers scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Headers scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_security_headers(self):
        """Test security headers"""
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
                },
                'Permissions-Policy': {
                    'description': 'Controls browser features and APIs',
                    'recommendation': 'Implement Permissions-Policy for enhanced security'
                }
            }
            
            for header, info in security_headers.items():
                if self.check_stop_flag():
                    return
                # Check if paused and wait
                self.check_pause_flag()
                
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
                else:
                    # Check header values for common misconfigurations
                    header_value = headers[header].lower()
                    
                    if header == 'X-Frame-Options' and 'deny' not in header_value and 'sameorigin' not in header_value:
                        self.vulnerabilities.append({
                            'category': 'Security Headers',
                            'risk_level': 'Medium',
                            'title': f'Weak {header} Configuration',
                            'description': f'{header} has weak value: {headers[header]}',
                            'location': self.target_url,
                            'evidence': f'{header} set to: {headers[header]}',
                            'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
                        })
                    
                    elif header == 'X-Content-Type-Options' and 'nosniff' not in header_value:
                        self.vulnerabilities.append({
                            'category': 'Security Headers',
                            'risk_level': 'Low',
                            'title': f'Weak {header} Configuration',
                            'description': f'{header} should be set to nosniff',
                            'location': self.target_url,
                            'evidence': f'{header} set to: {headers[header]}',
                            'recommendation': 'Set X-Content-Type-Options to nosniff'
                        })
                    
        except Exception as e:
            print(f"[-] Security headers test error: {e}")