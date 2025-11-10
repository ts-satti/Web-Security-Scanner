# scanners/standard/sqli_scanner.py
from ..base_scanner import SecurityScanner

class SQLIScanner(SecurityScanner):
    """Standard SQL injection scanner"""
    
    def run_scan(self):
        """Run focused SQL injection scan"""
        try:
            print(f"[*] Starting SQL injection scan for: {self.target_url}")
            self.update_progress(10, "🚀 Starting SQL injection scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test SQL injection vulnerabilities
            self.update_progress(50, "💉 Testing for SQL injection...")
            self.test_sql_injection()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating SQL injection report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ SQL injection scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] SQL injection scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        sql_payloads = self._get_sqli_payloads()
        forms = self.extract_forms()
        for i, form in enumerate(forms):
            if self.check_stop_flag():
                return
            # Check if paused and wait
            self.check_pause_flag()
            
            vulnerabilities = self.test_form_submission(form, sql_payloads, 'SQL Injection')
            self.vulnerabilities.extend(vulnerabilities)

    def _get_sqli_payloads(self):
        """Get basic SQL injection payloads"""
        return {
            'basic_union': "' UNION SELECT 1,2,3--",
            'or_condition': "' OR '1'='1",
            'time_based': "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            'error_based': "' AND 1=CONVERT(int,@@version)--",
            'comment_attack': "admin'--",
            'stacked_queries': "'; DROP TABLE users--"
        }