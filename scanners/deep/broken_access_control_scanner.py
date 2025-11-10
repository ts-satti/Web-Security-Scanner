# scanners/deep/broken_access_control_scanner.py
from urllib.parse import urljoin
from ..base_scanner import SecurityScanner

class BrokenAccessControlScanner(SecurityScanner):
    """Broken access control security scanner"""
    
    def run_scan(self):
        """Run broken access control security scan"""
        try:
            print(f"[*] Starting broken access control scan for: {self.target_url}")
            self.update_progress(10, "🚫 Starting broken access control scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test broken access control
            self.update_progress(50, "🔍 Testing access control vulnerabilities...")
            self.test_broken_access_control()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating access control report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Broken access control scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Broken access control scan error: {e}")
            return self._build_results('error', error_message=str(e))

    def test_broken_access_control(self):
        """Test for broken access control vulnerabilities"""
        try:
            # Test for IDOR (Insecure Direct Object Reference)
            test_paths = [
                '/user/1', '/admin/1', '/profile/1', '/order/1', 
                '/account/1', '/invoice/1', '/document/1'
            ]
            
            for path in test_paths:
                if self.check_stop_flag(): 
                    return
                
                test_url = urljoin(self.target_url, path)
                success, response = self.safe_request('GET', test_url)
                
                if success and response.status_code == 200:
                    # Check if we can access other users' data
                    self.vulnerabilities.append({
                        'category': 'Broken Access Control',
                        'risk_level': 'High',
                        'title': 'Potential Insecure Direct Object Reference (IDOR)',
                        'description': f'Accessible resource without proper authorization: {path}',
                        'location': test_url,
                        'evidence': f'Resource {path} accessible without access control',
                        'recommendation': 'Implement proper authorization checks for all object references'
                    })
            
        except Exception as e:
            print(f"[-] Broken access control test error: {e}")