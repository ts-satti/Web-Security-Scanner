# scanners/deep/cryptographic_failures_scanner.py
from ..base_scanner import SecurityScanner

class CryptographicFailuresScanner(SecurityScanner):
    """Cryptographic failures security scanner"""
    
    def run_scan(self):
        """Run cryptographic failures security scan"""
        try:
            print(f"[*] Starting cryptographic failures scan for: {self.target_url}")
            self.update_progress(10, "🔓 Starting cryptographic failures scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test cryptographic failures
            self.update_progress(50, "🔍 Testing cryptographic vulnerabilities...")
            self.test_cryptographic_failures()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating cryptographic failures report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Cryptographic failures scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Cryptographic failures scan error: {e}")
            return self._build_results('error', error_message=str(e))

    def test_cryptographic_failures(self):
        """Test for cryptographic failures"""
        try:
            # Check for HTTPS enforcement
            if not self.target_url.startswith('https://'):
                self.vulnerabilities.append({
                    'category': 'Cryptographic Failures',
                    'risk_level': 'High',
                    'title': 'No HTTPS Enforcement',
                    'description': 'Website does not enforce HTTPS',
                    'location': self.target_url,
                    'evidence': 'HTTP protocol used instead of HTTPS',
                    'recommendation': 'Implement HTTPS redirect and HSTS header'
                })
            
            # Check for weak cryptographic algorithms in responses
            success, response = self.safe_request('GET', self.target_url)
            if success:
                # Check for weak SSL/TLS (simplified)
                if 'server' in response.headers:
                    server_header = response.headers['server'].lower()
                    if 'apache' in server_header or 'nginx' in server_header:
                        # Generic server info
                        self.vulnerabilities.append({
                            'category': 'Cryptographic Failures',
                            'risk_level': 'Info',
                            'title': 'Server Information Disclosure',
                            'description': 'Server header exposes technology stack',
                            'location': self.target_url,
                            'evidence': f'Server header: {response.headers["server"]}',
                            'recommendation': 'Minimize server header information'
                        })
            
        except Exception as e:
            print(f"[-] Cryptographic failures test error: {e}")