# scanners/deep/websocket_scanner.py
import json
import requests
from urllib.parse import urljoin, urlparse
from ..base_scanner import SecurityScanner

class WebSocketScanner(SecurityScanner):
    """Advanced WebSocket security scanner with HTTP-based detection"""
    
    def __init__(self, target_url, scan_id, config=None):  # ✅ Added scan_id parameter
        super().__init__(target_url, scan_id, config)      # ✅ Pass to parent
        self.websocket_endpoints = []
        self.websocket_upgrade_headers = []

    def run_scan(self):
        """Run advanced WebSocket security scan"""
        try:
            print(f"[*] Starting advanced WebSocket security scan for: {self.target_url}")
            self.update_progress(10, "🔌 Discovering WebSocket endpoints...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Discover WebSocket endpoints
            self.discover_websocket_endpoints()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            if not self.websocket_endpoints:
                self.update_progress(100, "❌ No WebSocket endpoints found")
                return self._build_results('completed', 100)
            
            self.update_progress(30, "🔍 Testing WebSocket upgrade headers...")
            self.test_websocket_upgrade()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(50, "🛡️ Testing CORS and Origin validation...")
            self.test_cors_origin_validation()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(70, "📋 Testing protocol security...")
            self.test_protocol_security()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(85, "🔒 Testing authentication mechanisms...")
            self.test_authentication_mechanisms()
            
            # Finalize
            self.update_progress(95, "📊 Generating WebSocket security report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, f"✅ WebSocket security scan completed! Found {len(self.websocket_endpoints)} endpoints")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] WebSocket security scan error: {e}")
            return self._build_results('error', error_message=str(e))

    # ... rest of your WebSocketScanner methods remain the same ...
    def discover_websocket_endpoints(self):
        """Discover WebSocket endpoints using multiple methods"""
        self._discover_from_html_content()
        self._discover_common_paths()
        self._discover_via_upgrade_requests()

    def _discover_from_html_content(self):
        """Discover WebSocket endpoints from page content"""
        scripts = self.extract_scripts()
        
        ws_keywords = [
            'new WebSocket(', 'ws://', 'wss://', 
            'websocket', 'socket.io', 'WebSocket',
            'io.connect(', 'io(', 'Socket.IO'
        ]
        
        discovered_urls = set()
        
        for script in scripts:
            for keyword in ws_keywords:
                if keyword in script:
                    import re
                    url_patterns = [
                        r'ws://[^\s"\']+',
                        r'wss://[^\s"\']+',
                        r'new WebSocket\(["\']([^"\']+)["\']\)',
                        r'io\.connect\(["\']([^"\']+)["\']\)'
                    ]
                    
                    for pattern in url_patterns:
                        matches = re.findall(pattern, script)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0] if match else ""
                            if match and (match.startswith('ws://') or match.startswith('wss://')):
                                discovered_urls.add(match)
                            elif match:
                                full_url = urljoin(self.target_url, match)
                                discovered_urls.add(full_url)
        
        for ws_url in discovered_urls:
            http_url = ws_url.replace('ws://', 'http://').replace('wss://', 'https://')
            self.websocket_endpoints.append({
                'ws_url': ws_url,
                'test_url': http_url,
                'discovery_method': 'html_analysis'
            })

    def _discover_common_paths(self):
        """Discover WebSocket endpoints using common paths"""
        common_paths = [
            '/ws', '/websocket', '/socket.io', '/wss', 
            '/api/ws', '/api/socket', '/live', '/realtime'
        ]
        
        for path in common_paths:
            if self.check_stop_flag():
                return
                
            test_url = urljoin(self.target_url, path)
            ws_url = test_url.replace('http://', 'ws://').replace('https://', 'wss://')
            
            success, response = self.safe_request('GET', test_url, headers={
                'Upgrade': 'websocket',
                'Connection': 'Upgrade'
            })
            
            if success and response.status_code in [101, 200, 404, 403]:
                self.websocket_endpoints.append({
                    'ws_url': ws_url,
                    'test_url': test_url,
                    'discovery_method': 'common_path',
                    'status_code': response.status_code
                })

    def _discover_via_upgrade_requests(self):
        """Discover WebSocket endpoints by testing Upgrade headers"""
        urls = self.extract_urls()
        
        for url in urls[:20]:
            if self.check_stop_flag():
                return
                
            success, response = self.safe_request('GET', url, headers={
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            })
            
            if success:
                if response.status_code == 101:
                    ws_url = url.replace('http://', 'ws://').replace('https://', 'wss://')
                    self.websocket_endpoints.append({
                        'ws_url': ws_url,
                        'test_url': url,
                        'discovery_method': 'upgrade_test',
                        'status_code': 101
                    })
                
                if any(header.lower() in response.headers for header in 
                      ['upgrade', 'sec-websocket-accept', 'websocket']):
                    ws_url = url.replace('http://', 'ws://').replace('https://', 'wss://')
                    self.websocket_endpoints.append({
                        'ws_url': ws_url,
                        'test_url': url,
                        'discovery_method': 'header_analysis',
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    })

    def test_websocket_upgrade(self):
        """Test WebSocket upgrade mechanism security"""
        for endpoint in self.websocket_endpoints:
            if self.check_stop_flag():
                return
                
            test_url = endpoint['test_url']
            
            upgrade_tests = [
                {
                    'name': 'Standard Upgrade',
                    'headers': {
                        'Upgrade': 'websocket',
                        'Connection': 'Upgrade',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                        'Sec-WebSocket-Version': '13'
                    }
                },
                {
                    'name': 'Missing Version',
                    'headers': {
                        'Upgrade': 'websocket',
                        'Connection': 'Upgrade',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ=='
                    }
                }
            ]
            
            for test in upgrade_tests:
                if self.check_stop_flag():
                    return
                    
                success, response = self.safe_request('GET', test_url, headers=test['headers'])
                
                if success:
                    self._analyze_upgrade_response(response, test['name'], endpoint)

    def test_cors_origin_validation(self):
        """Test CORS and Origin validation for WebSocket endpoints"""
        malicious_origins = [
            'http://malicious.com',
            'https://attacker.org',
            'null',
            'http://evil.example.com'
        ]
        
        for endpoint in self.websocket_endpoints:
            if self.check_stop_flag():
                return
                
            test_url = endpoint['test_url']
            
            for origin in malicious_origins:
                if self.check_stop_flag():
                    return
                    
                success, response = self.safe_request('GET', test_url, headers={
                    'Origin': origin,
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade'
                })
                
                if success and response.status_code == 101:
                    self.vulnerabilities.append({
                        'category': 'WebSocket Security',
                        'risk_level': 'High',
                        'title': 'Cross-Site WebSocket Hijacking (CSWSH)',
                        'description': f'WebSocket accepts connections from different origin: {origin}',
                        'location': endpoint['ws_url'],
                        'evidence': f'Accepted Origin: {origin}',
                        'recommendation': 'Implement strict Origin validation and CSRF tokens'
                    })

    def test_protocol_security(self):
        """Test WebSocket protocol security issues"""
        for endpoint in self.websocket_endpoints:
            if self.check_stop_flag():
                return
                
            test_url = endpoint['test_url']
            
            protocol_tests = [
                {'version': '8', 'name': 'Older Protocol'},
                {'version': '0', 'name': 'Invalid Protocol'},
                {'version': '14', 'name': 'Future Protocol'}
            ]
            
            for test in protocol_tests:
                if self.check_stop_flag():
                    return
                    
                success, response = self.safe_request('GET', test_url, headers={
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': test['version']
                })
                
                if success and response.status_code == 101:
                    self.vulnerabilities.append({
                        'category': 'WebSocket Security',
                        'risk_level': 'Medium',
                        'title': f'WebSocket Protocol Issue - {test["name"]}',
                        'description': f'WebSocket accepted connection with protocol version: {test["version"]}',
                        'location': endpoint['ws_url'],
                        'evidence': f'Accepted version: {test["version"]}',
                        'recommendation': 'Strictly enforce WebSocket protocol version 13'
                    })

    def test_authentication_mechanisms(self):
        """Test WebSocket authentication and authorization"""
        auth_bypass_payloads = [
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer undefined'},
            {'X-Auth-Token': 'admin'},
            {'X-API-Key': 'test'}
        ]
        
        for endpoint in self.websocket_endpoints:
            if self.check_stop_flag():
                return
                
            test_url = endpoint['test_url']
            
            # First test without authentication
            success, response = self.safe_request('GET', test_url, headers={
                'Upgrade': 'websocket',
                'Connection': 'Upgrade'
            })
            
            if success and response.status_code == 101:
                self.vulnerabilities.append({
                    'category': 'WebSocket Security',
                    'risk_level': 'High',
                    'title': 'WebSocket Accessible Without Authentication',
                    'description': 'WebSocket endpoint accessible without any authentication',
                    'location': endpoint['ws_url'],
                    'evidence': 'Successfully upgraded without authentication headers',
                    'recommendation': 'Implement proper authentication for WebSocket connections'
                })
            
            # Test authentication bypass attempts
            for auth_payload in auth_bypass_payloads:
                if self.check_stop_flag():
                    return
                    
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13'
                }
                headers.update(auth_payload)
                
                success, response = self.safe_request('GET', test_url, headers=headers)
                
                if success and response.status_code == 101:
                    self.vulnerabilities.append({
                        'category': 'WebSocket Security',
                        'risk_level': 'High',
                        'title': 'Potential WebSocket Authentication Bypass',
                        'description': f'WebSocket accepted connection with suspicious auth: {list(auth_payload.keys())[0]}',
                        'location': endpoint['ws_url'],
                        'evidence': f'Bypass attempt: {auth_payload}',
                        'recommendation': 'Implement proper token validation and authentication'
                    })

    def _analyze_upgrade_response(self, response, test_name, endpoint):
        """Analyze WebSocket upgrade response for vulnerabilities"""
        if response.status_code == 101:
            self.vulnerabilities.append({
                'category': 'WebSocket Security',
                'risk_level': 'Info',
                'title': f'WebSocket Upgrade Successful - {test_name}',
                'description': f'WebSocket endpoint accepted {test_name} upgrade request',
                'location': endpoint['ws_url'],
                'evidence': f'Upgrade test: {test_name}',
                'recommendation': 'Ensure proper WebSocket protocol validation'
            })
            
            security_headers = ['Sec-WebSocket-Accept', 'Upgrade', 'Connection']
            
            for header in security_headers:
                if header not in response.headers:
                    self.vulnerabilities.append({
                        'category': 'WebSocket Security',
                        'risk_level': 'Low',
                        'title': f'Missing WebSocket Header - {header}',
                        'description': f'WebSocket response missing expected header: {header}',
                        'location': endpoint['ws_url'],
                        'evidence': f'Missing header: {header}',
                        'recommendation': 'Ensure all required WebSocket headers are present'
                    })
        
        elif response.status_code in [200, 201]:
            self.vulnerabilities.append({
                'category': 'WebSocket Security',
                'risk_level': 'Medium',
                'title': 'Unexpected Response to Upgrade Request',
                'description': f'Server returned {response.status_code} instead of 101 for WebSocket upgrade',
                'location': endpoint['ws_url'],
                'evidence': f'Status code: {response.status_code} for {test_name}',
                'recommendation': 'Ensure proper WebSocket protocol implementation'
            })

    def extract_scripts(self):
        """Extract JavaScript content from the page"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if success:
                content = response.text
                import re
                script_pattern = r'<script[^>]*>(.*?)</script>'
                scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
                return scripts
        except:
            pass
        return []