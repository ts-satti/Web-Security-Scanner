# scanners/standard/xss_scanner.py
from ..base_scanner import SecurityScanner

class XSSScanner(SecurityScanner):
    """Standard XSS vulnerability scanner"""
    
    def run_scan(self):
        """Run focused XSS scan"""
        try:
            print(f"[*] Starting XSS scan for: {self.target_url}")
            self.update_progress(10, "🦠 Starting XSS scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test XSS vulnerabilities
            self.update_progress(50, "🦠 Testing for XSS vulnerabilities...")
            self.test_xss()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating XSS report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ XSS scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] XSS scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_xss(self):
        """Test for XSS vulnerabilities with standard payloads"""
        xss_payloads = self._get_xss_payloads()
        forms = self.extract_forms()
        for form in forms:
            if self.check_stop_flag():
                return
            # Check if paused and wait
            self.check_pause_flag()
            vulnerabilities = self.test_form_submission(form, xss_payloads, 'XSS')
            self.vulnerabilities.extend(vulnerabilities)
    
    def _get_xss_payloads(self):
        """Get standard XSS payloads"""
        return {
            'basic_script': '<script>alert("XSS")</script>',
            'basic_script': '<script>alert(123)</script>',
            'img_onerror': '<img src=x onerror=alert("XSS")>',
            'svg_onload': '<svg onload=alert("XSS")>',
            'body_onload': '<body onload=alert("XSS")>',
            'javascript_url': 'javascript:alert("XSS")',
            'input_event': '<input onfocus=alert("XSS") autofocus>',
            'iframe_src': '<iframe src="javascript:alert(`XSS`)">'
        }