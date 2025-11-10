# scanners/deep/api_security_scanner.py - UPDATED VERSION

import time
import json
import re
from urllib.parse import urljoin
from ..base_scanner import SecurityScanner

class APISecurityScanner(SecurityScanner):
    """Specialized API security scanner with enhanced GraphQL testing"""
    
    def run_scan(self):
        """Run comprehensive API security scan"""
        try:
            print(f"[*] Starting API security scan for: {self.target_url}")
            self.update_progress(10, "🔐 Starting API security scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test API security
            self.update_progress(50, "🔍 Testing API endpoints...")
            self.test_api_security()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating API security report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ API security scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] API security scan error: {e}")
            return self._build_results('error', error_message=str(e))

    def test_api_security(self):
        """Comprehensive API security testing"""
        try:
            # Common API endpoints to test
            api_endpoints = [
                '/api/users', '/api/auth', '/api/login', '/api/register',
                '/api/admin', '/api/config', '/api/data', '/api/keys',
                '/api/tokens', '/api/password/reset', '/api/health',
                '/api/status', '/api/debug', '/api/test', '/graphql',
                '/rest/v1', '/v1/api', '/v2/api', '/oauth/token'
            ]
            
            found_vulnerabilities = False
            
            for endpoint in api_endpoints:
                if self.check_stop_flag():
                    return
                    
                test_url = urljoin(self.target_url, endpoint)
                
                # Test each endpoint with different HTTP methods
                for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    if self.check_stop_flag():
                        return
                    
                    success, response = self.safe_request(method, test_url, data={'test': 'payload'})
                    
                    if success:
                        # Analyze response for API security issues
                        vulnerabilities_found = self._analyze_api_response(method, test_url, response)
                        if vulnerabilities_found:
                            found_vulnerabilities = True
                    
                    time.sleep(0.2)  # Rate limiting
                
                # Test for API authentication bypass
                self._test_api_auth_bypass(test_url)
            
            # Test for GraphQL-specific vulnerabilities - ENHANCED
            self._test_graphql_security_enhanced()
            
            # Test for REST API specific issues
            self._test_rest_api_security()
            
            # NEW: Test for batch operations vulnerabilities
            self._test_batch_operations()
            
            if not found_vulnerabilities:
                self.vulnerabilities.append({
                    'category': 'API Security',
                    'risk_level': 'Info',
                    'title': 'No API Security Vulnerabilities Found',
                    'description': 'Basic API security tests completed without finding critical vulnerabilities',
                    'location': self.target_url,
                    'evidence': 'API endpoints responded appropriately to security tests',
                    'recommendation': 'Implement comprehensive API security testing including authentication, authorization, and input validation'
                })
                
        except Exception as e:
            print(f"[-] API security test error: {e}")
            self.vulnerabilities.append({
                'category': 'API Security',
                'risk_level': 'Info',
                'title': 'API Security Testing Incomplete',
                'description': f'API security testing encountered an error: {str(e)}',
                'location': self.target_url,
                'evidence': 'Test execution failed',
                'recommendation': 'Review API endpoints manually for security issues'
            })

    def _analyze_api_response(self, method, url, response):
        """Analyze API response for security vulnerabilities"""
        vulnerabilities_found = False
        
        # Check for information disclosure in errors
        if response.status_code >= 500:
            error_content = response.text.lower()
            sensitive_indicators = ['stack trace', 'database error', 'sql syntax', 'file path', 'class name']
            
            if any(indicator in error_content for indicator in sensitive_indicators):
                self.vulnerabilities.append({
                    'category': 'API Security',
                    'risk_level': 'Medium',
                    'title': 'API Information Disclosure in Error Messages',
                    'description': f'API endpoint discloses sensitive information in {method} response',
                    'location': url,
                    'evidence': f'Error response contains stack traces or internal details: {response.status_code}',
                    'recommendation': 'Configure proper error handling to avoid information disclosure'
                })
                vulnerabilities_found = True
        
        # Check for missing security headers in API responses
        security_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security']
        missing_headers = [h for h in security_headers if h not in response.headers]
        
        if missing_headers:
            self.vulnerabilities.append({
                'category': 'API Security',
                'risk_level': 'Low',
                'title': 'Missing Security Headers in API Response',
                'description': f'API endpoint missing security headers: {", ".join(missing_headers)}',
                'location': url,
                'evidence': f'Missing headers: {missing_headers}',
                'recommendation': 'Implement security headers for all API responses'
            })
            vulnerabilities_found = True
        
        # Check for excessive data exposure
        if len(response.text) > 10000:  # Large response might indicate data over-exposure
            try:
                # Try to parse as JSON to check if it's exposing too much data
                data = json.loads(response.text)
                if isinstance(data, list) and len(data) > 100:
                    self.vulnerabilities.append({
                        'category': 'API Security',
                        'risk_level': 'Medium',
                        'title': 'Potential Excessive Data Exposure',
                        'description': 'API endpoint may be exposing excessive data without pagination',
                        'location': url,
                        'evidence': f'Large response payload ({len(response.text)} bytes) with array of {len(data)} items',
                        'recommendation': 'Implement pagination, filtering, and proper access controls'
                    })
                    vulnerabilities_found = True
            except:
                pass
        
        return vulnerabilities_found

    def _test_api_auth_bypass(self, api_url):
        """Test for API authentication bypass vulnerabilities"""
        try:
            # Test without authentication
            success, response = self.safe_request('GET', api_url)
            
            if success and response.status_code == 200:
                # Test with various bypass attempts
                bypass_attempts = [
                    {'X-Forwarded-For': '127.0.0.1'},
                    {'X-Real-IP': '127.0.0.1'},
                    {'User-Agent': 'GoogleBot'},
                    {'X-API-Key': 'test'},
                    {'Authorization': 'Bearer test'}
                ]
                
                for headers in bypass_attempts:
                    success, response = self.safe_request('GET', api_url, headers=headers)
                    if success and response.status_code == 200:
                        self.vulnerabilities.append({
                            'category': 'API Security',
                            'risk_level': 'High',
                            'title': 'Potential API Authentication Bypass',
                            'description': 'API endpoint accessible with simple header manipulation',
                            'location': api_url,
                            'evidence': f'Endpoint accessible with headers: {headers}',
                            'recommendation': 'Implement proper authentication and authorization checks'
                        })
                        break
                        
        except Exception as e:
            print(f"[-] API auth bypass test error: {e}")

    def _test_graphql_security_enhanced(self):
        """ENHANCED: Test for GraphQL-specific security issues"""
        try:
            graphql_url = urljoin(self.target_url, '/graphql')
            success, response = self.safe_request('GET', graphql_url)
            
            if success and response.status_code != 404:
                # GraphQL endpoint found
                introspection_query = {
                    "query": """
                    query IntrospectionQuery {
                        __schema {
                            types {
                                name
                                fields {
                                    name
                                    type {
                                        name
                                    }
                                }
                            }
                        }
                    }
                    """
                }
                
                success, response = self.safe_request('POST', graphql_url, 
                                                    json=introspection_query,
                                                    headers={'Content-Type': 'application/json'})
                
                if success and response.status_code == 200:
                    # Check if introspection is enabled
                    if '__schema' in response.text:
                        self.vulnerabilities.append({
                            'category': 'API Security',
                            'risk_level': 'Medium',
                            'title': 'GraphQL Introspection Enabled',
                            'description': 'GraphQL introspection endpoint is accessible, exposing API schema',
                            'location': graphql_url,
                            'evidence': 'GraphQL introspection query returned schema information',
                            'recommendation': 'Disable introspection in production environments'
                        })
                
                # NEW: Test for GraphQL batch query attacks
                batch_queries = [
                    {"query": "query { users { id name email } }"},
                    {"query": "query { posts { id title content } }"},
                    {"query": "query { config { key value } }"}
                ]
                
                success, response = self.safe_request('POST', graphql_url, 
                                                    json=batch_queries,
                                                    headers={'Content-Type': 'application/json'})
                
                if success and response.status_code == 200:
                    try:
                        batch_response = json.loads(response.text)
                        if isinstance(batch_response, list) and len(batch_response) == len(batch_queries):
                            self.vulnerabilities.append({
                                'category': 'API Security',
                                'risk_level': 'Medium',
                                'title': 'GraphQL Batch Query Enabled',
                                'description': 'GraphQL endpoint processes batch queries which may enable DoS attacks',
                                'location': graphql_url,
                                'evidence': f'Batch queries accepted and processed ({len(batch_queries)} queries)',
                                'recommendation': 'Implement query cost analysis and rate limiting for batch operations'
                            })
                    except:
                        pass
                
                # NEW: Test for GraphQL alias overload
                alias_query = {
                    "query": """
                    query {
                        a1: users { id name }
                        a2: users { id name }
                        a3: users { id name }
                        a4: users { id name }
                        a5: users { id name }
                        a6: users { id name }
                        a7: users { id name }
                        a8: users { id name }
                        a9: users { id name }
                        a10: users { id name }
                    }
                    """
                }
                
                success, response = self.safe_request('POST', graphql_url, 
                                                    json=alias_query,
                                                    headers={'Content-Type': 'application/json'})
                
                if success and response.status_code == 200:
                    self.vulnerabilities.append({
                        'category': 'API Security',
                        'risk_level': 'Low',
                        'title': 'GraphQL Alias Overload Possible',
                        'description': 'GraphQL endpoint accepts multiple aliases for the same query',
                        'location': graphql_url,
                        'evidence': 'Endpoint processed query with 10 aliases of same field',
                        'recommendation': 'Implement alias limits and query depth restrictions'
                    })
                
                # Test for GraphQL injection
                injection_payloads = [
                    {"query": "query { users { id name } }" * 10},  # Batch query attack
                    {"query": "query { __typename }"},  # Type introspection
                ]
                
                for payload in injection_payloads:
                    success, response = self.safe_request('POST', graphql_url, 
                                                        json=payload,
                                                        headers={'Content-Type': 'application/json'})
                    
                    if success and 'error' not in response.text.lower():
                        self.vulnerabilities.append({
                            'category': 'API Security',
                            'risk_level': 'Low',
                            'title': 'GraphQL Endpoint Potentially Vulnerable to DoS',
                            'description': 'GraphQL endpoint accepted potentially malicious query',
                            'location': graphql_url,
                            'evidence': 'Endpoint processed complex or recursive query',
                            'recommendation': 'Implement query depth limiting and query whitelisting'
                        })
                        break
                        
        except Exception as e:
            print(f"[-] GraphQL security test error: {e}")

    def _test_rest_api_security(self):
        """Test for REST API-specific security issues"""
        try:
            # Test for mass assignment vulnerabilities
            user_endpoints = ['/api/users', '/api/profile', '/api/account']
            
            for endpoint in user_endpoints:
                test_url = urljoin(self.target_url, endpoint)
                mass_assignment_payload = {
                    'id': 1,
                    'username': 'test',
                    'email': 'test@test.com',
                    'role': 'admin',
                    'is_admin': True,
                    'password': 'newpassword'
                }
                
                success, response = self.safe_request('POST', test_url, json=mass_assignment_payload)
                
                if success and response.status_code in [200, 201]:
                    # Check if admin privileges were granted
                    self.vulnerabilities.append({
                        'category': 'API Security',
                        'risk_level': 'High',
                        'title': 'Potential Mass Assignment Vulnerability',
                        'description': 'API endpoint may be vulnerable to mass assignment attacks',
                        'location': test_url,
                        'evidence': f'Endpoint accepted privileged fields: {list(mass_assignment_payload.keys())}',
                        'recommendation': 'Use allow-lists for input fields and implement proper object-level authorization'
                    })
                    break
                    
        except Exception as e:
            print(f"[-] REST API security test error: {e}")

    def _test_batch_operations(self):
        """NEW: Test for batch operations vulnerabilities"""
        try:
            # Test for batch endpoint
            batch_endpoints = ['/api/batch', '/batch', '/api/v1/batch']
            
            for endpoint in batch_endpoints:
                test_url = urljoin(self.target_url, endpoint)
                
                batch_payload = {
                    "requests": [
                        {"method": "GET", "path": "/api/users/1"},
                        {"method": "GET", "path": "/api/users/2"},
                        {"method": "GET", "path": "/api/admin/config"},
                        {"method": "POST", "path": "/api/users", "body": {"username": "hacker"}}
                    ]
                }
                
                success, response = self.safe_request('POST', test_url, json=batch_payload)
                
                if success and response.status_code == 200:
                    self.vulnerabilities.append({
                        'category': 'API Security',
                        'risk_level': 'Medium',
                        'title': 'Batch Operations Enabled',
                        'description': 'API batch endpoint may enable privilege escalation or DoS attacks',
                        'location': test_url,
                        'evidence': 'Batch endpoint accepted multiple operations',
                        'recommendation': 'Implement strict authorization checks for batch operations and rate limiting'
                    })
                    break
                    
        except Exception as e:
            print(f"[-] Batch operations test error: {e}")