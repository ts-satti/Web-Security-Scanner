# scanners/deep/graphql_security_scanner.py
import json
import requests
import time
from urllib.parse import urljoin
from ..base_scanner import SecurityScanner

class GraphQLSecurityScanner(SecurityScanner):
    """Advanced GraphQL security scanner with comprehensive testing"""
    
    def __init__(self, target_url, scan_id, config=None):  # ✅ Added scan_id parameter
        super().__init__(target_url, scan_id, config)      # ✅ Pass to parent
        self.graphql_endpoints = []
        self.introspection_data = {}
        self.queries_tested = 0

    def run_scan(self):
        """Run advanced GraphQL security scan"""
        try:
            print(f"[*] Starting advanced GraphQL security scan for: {self.target_url}")
            self.update_progress(10, "🕸️ Discovering GraphQL endpoints...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Discover GraphQL endpoints
            self.discover_graphql_endpoints()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            if not self.graphql_endpoints:
                self.update_progress(100, "❌ No GraphQL endpoints found")
                return self._build_results('completed', 100)
            
            self.update_progress(30, "🔍 Testing GraphQL introspection...")
            self.test_introspection()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(50, "⚡ Testing GraphQL injection attacks...")
            self.test_graphql_injection()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(70, "📈 Testing query complexity attacks...")
            self.test_query_complexity()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            self.update_progress(85, "🛡️ Testing authorization bypass...")
            self.test_authorization_bypass()
            
            # Finalize
            self.update_progress(95, "📊 Generating GraphQL security report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, f"✅ GraphQL security scan completed! Tested {self.queries_tested} queries")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] GraphQL security scan error: {e}")
            return self._build_results('error', error_message=str(e))

    def discover_graphql_endpoints(self):
        """Discover GraphQL endpoints using common paths"""
        common_endpoints = [
            '/graphql', '/api/graphql', '/query', '/gql',
            '/v1/graphql', '/v2/graphql', '/v3/graphql',
            '/graphql-api', '/gql-api', '/api',
            '/graphql.php', '/graphql/engine', '/hasura'
        ]
        
        for endpoint in common_endpoints:
            if self.check_stop_flag():
                return
                
            url = urljoin(self.target_url, endpoint)
            
            # Test with introspection query
            introspection_query = {
                "query": "query { __schema { types { name } } }"
            }
            
            # Test POST request
            success, response = self.safe_request('POST', url, json=introspection_query)
            if success and response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data and '__schema' in data.get('data', {}):
                        self.graphql_endpoints.append({
                            'url': url,
                            'type': 'graphql',
                            'method': 'POST',
                            'details': 'Active GraphQL endpoint discovered'
                        })
                        print(f"[+] Found GraphQL endpoint: {url} (POST)")
                except:
                    pass
            
            # Test GET requests
            success, response = self.safe_request('GET', url, params={'query': '{ __schema { types { name } } }'})
            if success and response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data:
                        self.graphql_endpoints.append({
                            'url': url,
                            'type': 'graphql',
                            'method': 'GET', 
                            'details': 'Active GraphQL endpoint (GET) discovered'
                        })
                        print(f"[+] Found GraphQL endpoint: {url} (GET)")
                except:
                    pass
            
            # Test with different content types
            headers_list = [
                {'Content-Type': 'application/json'},
                {'Content-Type': 'application/graphql'},
                {'Content-Type': 'application/x-www-form-urlencoded'}
            ]
            
            for headers in headers_list:
                if self.check_stop_flag():
                    return
                    
                success, response = self.safe_request('POST', url, json=introspection_query, headers=headers)
                if success and response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and data.get('data'):
                            # Check if we already found this endpoint
                            if not any(ep['url'] == url and ep['method'] == 'POST' for ep in self.graphql_endpoints):
                                self.graphql_endpoints.append({
                                    'url': url,
                                    'type': 'graphql',
                                    'method': 'POST',
                                    'details': f'GraphQL endpoint with {headers["Content-Type"]}'
                                })
                                print(f"[+] Found GraphQL endpoint: {url} ({headers['Content-Type']})")
                    except:
                        pass

    def test_introspection(self):
        """Test GraphQL introspection security"""
        for endpoint in self.graphql_endpoints:
            if self.check_stop_flag():
                return
                
            url = endpoint['url']
            method = endpoint.get('method', 'POST')
            
            # Full introspection query
            full_introspection = {
                "query": """
                query IntrospectionQuery {
                  __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                      ...FullType
                    }
                    directives {
                      name
                      description
                      locations
                      args {
                        ...InputValue
                      }
                    }
                  }
                }
                fragment FullType on __Type {
                  kind
                  name
                  description
                  fields(includeDeprecated: true) {
                    name
                    description
                    args {
                      ...InputValue
                    }
                    type {
                      ...TypeRef
                    }
                    isDeprecated
                    deprecationReason
                  }
                  inputFields {
                    ...InputValue
                  }
                  interfaces {
                    ...TypeRef
                  }
                  enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                  }
                  possibleTypes {
                    ...TypeRef
                  }
                }
                fragment InputValue on __InputValue {
                  name
                  description
                  type { ...TypeRef }
                  defaultValue
                }
                fragment TypeRef on __Type {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                          ofType {
                            kind
                            name
                            ofType {
                              kind
                              name
                              ofType {
                                kind
                                name
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
                """
            }
            
            success = False
            response = None
            
            if method == 'POST':
                success, response = self.safe_request('POST', url, json=full_introspection)
            else:
                # For GET, we need to URL encode the query
                import urllib.parse
                encoded_query = urllib.parse.quote(full_introspection['query'])
                success, response = self.safe_request('GET', url, params={'query': encoded_query})
            
            if success and response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data and data['data']:
                        self.introspection_data[url] = data
                        self.vulnerabilities.append({
                            'category': 'GraphQL Security',
                            'risk_level': 'High',
                            'title': 'GraphQL Introspection Enabled',
                            'description': 'GraphQL introspection is enabled, exposing the entire schema to attackers',
                            'location': url,
                            'evidence': 'Full schema introspection successful - complete schema exposed',
                            'recommendation': 'Disable introspection in production environments using graphql-disable-introspection'
                        })
                        print(f"[!] Introspection enabled at: {url}")
                except Exception as e:
                    print(f"[-] Introspection test error for {url}: {e}")

    def test_graphql_injection(self):
        """Test various GraphQL injection attacks"""
        injection_payloads = [
            # SQL Injection through GraphQL
            {"query": "query { users(filter: \"' OR '1'='1'\") { id name } }"},
            {"query": "query { users(filter: \"'; DROP TABLE users-- \") { id } }"},
            
            # NoSQL Injection
            {"query": "query { posts(filter: {\"$where\": \"function() { return true; }\"}) { title } }"},
            {"query": "query { users(filter: {\"$ne\": null}) { id name } }"},
            
            # Command Injection (safe patterns)
            {"query": "query { system(cmd: \"echo test\") { output } }"},
            {"query": "query { exec(input: \"whoami\") { result } }"},
            
            # Field duplication attack
            {"query": "query { __schema { types { name name } } }"},
            
            # Aliases for field duplication
            {"query": "query { a: __schema { types { name } } b: __schema { types { name } } }"},
            
            # Directives abuse
            {"query": "query { __schema { types { name @include(if: true) } } }"},
            
            # Fragment attacks
            {"query": "query { ...frag1 ...frag1 } fragment frag1 on Query { __schema { types { name } } }"},
            
            # Type confusion
            {"query": "query { __typename }"},
        ]
        
        for endpoint in self.graphql_endpoints:
            for payload in injection_payloads:
                if self.check_stop_flag():
                    return
                    
                self.queries_tested += 1
                
                method = endpoint.get('method', 'POST')
                success = False
                response = None
                
                if method == 'POST':
                    success, response = self.safe_request('POST', endpoint['url'], json=payload)
                else:
                    # For GET requests, URL encode the query
                    import urllib.parse
                    encoded_query = urllib.parse.quote(payload['query'])
                    success, response = self.safe_request('GET', endpoint['url'], params={'query': encoded_query})
                
                if success and response.status_code == 200:
                    try:
                        data = response.json()
                        # Check if query executed without GraphQL errors
                        if 'errors' not in data and 'data' in data:
                            self.vulnerabilities.append({
                                'category': 'GraphQL Injection',
                                'risk_level': 'Medium',
                                'title': 'Potential GraphQL Injection',
                                'description': 'GraphQL query executed without errors with potentially dangerous payload',
                                'location': endpoint['url'],
                                'evidence': f'Payload: {json.dumps(payload)[:200]}...',
                                'recommendation': 'Implement proper input validation, query whitelisting, and depth limiting'
                            })
                    except:
                        pass
                
                # Small delay to be nice to the server
                time.sleep(0.1)

    def test_query_complexity(self):
        """Test for query complexity and DoS vulnerabilities"""
        for endpoint in self.graphql_endpoints:
            if self.check_stop_flag():
                return
                
            # Deep nesting attack (10 levels)
            deep_query = "query { " + "a: __schema { types { " * 10 + "name " + "} " * 10 + "} }"
            
            # Field explosion attack
            field_explosion = {"query": "query { __schema { types { name fields { name type { name fields { name type { name } } } } } } }"}
            
            # Circular fragment attack
            circular_fragment = {
                "query": """
                query {
                    ...frag1
                }
                fragment frag1 on Query {
                    __schema {
                        types {
                            name
                            ...frag2
                        }
                    }
                }
                fragment frag2 on __Type {
                    fields {
                        name
                        type {
                            ...frag1
                        }
                    }
                }
                """
            }
            
            # Batch query attack (reduced to 20 for safety)
            batch_queries = [{"query": "query { __schema { types { name } } }"} for _ in range(20)]
            
            method = endpoint.get('method', 'POST')
            
            # Test deep nesting
            if method == 'POST':
                success, response = self.safe_request('POST', endpoint['url'], json={"query": deep_query})
            else:
                import urllib.parse
                encoded_query = urllib.parse.quote(deep_query)
                success, response = self.safe_request('GET', endpoint['url'], params={'query': encoded_query})
                
            if success and response.status_code == 200:
                try:
                    data = response.json()
                    if 'errors' not in data:
                        self.vulnerabilities.append({
                            'category': 'GraphQL DoS',
                            'risk_level': 'High',
                            'title': 'Potential Query Complexity DoS - Deep Nesting',
                            'description': 'Deeply nested query executed without complexity/depth limits',
                            'location': endpoint['url'],
                            'evidence': '10-level deep nesting query executed successfully',
                            'recommendation': 'Implement query depth limiting and complexity analysis'
                        })
                except:
                    pass
            
            # Test field explosion
            if method == 'POST':
                success, response = self.safe_request('POST', endpoint['url'], json=field_explosion)
            else:
                import urllib.parse
                encoded_query = urllib.parse.quote(field_explosion['query'])
                success, response = self.safe_request('GET', endpoint['url'], params={'query': encoded_query})
                
            if success and response.status_code == 200:
                try:
                    data = response.json()
                    if 'errors' not in data:
                        self.vulnerabilities.append({
                            'category': 'GraphQL DoS',
                            'risk_level': 'High',
                            'title': 'Potential Query Complexity DoS - Field Explosion',
                            'description': 'Field explosion query executed without field limiting',
                            'location': endpoint['url'],
                            'evidence': 'Field explosion query executed successfully',
                            'recommendation': 'Implement field limiting and query cost analysis'
                        })
                except:
                    pass
            
            # Test batch queries (POST only for batch)
            if method == 'POST':
                success, response = self.safe_request('POST', endpoint['url'], json=batch_queries)
                if success and response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):  # Batch responses are arrays
                            self.vulnerabilities.append({
                                'category': 'GraphQL DoS',
                                'risk_level': 'Medium',
                                'title': 'Batch Query Execution Allowed',
                                'description': 'Multiple queries executed in single request without rate limiting',
                                'location': endpoint['url'],
                                'evidence': f'{len(batch_queries)} batch queries executed successfully',
                                'recommendation': 'Implement query batching limits and rate limiting'
                            })
                    except:
                        pass

    def test_authorization_bypass(self):
        """Test for authorization bypass in GraphQL"""
        sensitive_queries = [
            # User operations
            {"query": "mutation { deleteUser(id: 1) { success } }"},
            {"query": "mutation { updateUser(id: 1, input: {isAdmin: true}) { id isAdmin } }"},
            {"query": "mutation { createUser(input: {username: \"hacker\", password: \"hacked\", isAdmin: true}) { id } }"},
            
            # Data access
            {"query": "query { users { id email password } }"},
            {"query": "query { customers { creditCard personalData } }"},
            
            # System configuration
            {"query": "query { configuration { secretKey apiKeys databasePassword } }"},
            {"query": "query { settings { debugMode secretTokens } }"},
            
            # Admin operations
            {"query": "mutation { shutdownServer { success } }"},
            {"query": "mutation { updateConfig(key: \"admin_password\", value: \"hacked\") { success } }"},
            
            # Sensitive fields
            {"query": "query { __schema { types { name fields { name } } } }"}  # Get all available fields
        ]
        
        for endpoint in self.graphql_endpoints:
            for query in sensitive_queries:
                if self.check_stop_flag():
                    return
                    
                self.queries_tested += 1
                
                method = endpoint.get('method', 'POST')
                success = False
                response = None
                
                if method == 'POST':
                    success, response = self.safe_request('POST', endpoint['url'], json=query)
                else:
                    import urllib.parse
                    encoded_query = urllib.parse.quote(query['query'])
                    success, response = self.safe_request('GET', endpoint['url'], params={'query': encoded_query})
                
                if success and response.status_code == 200:
                    try:
                        data = response.json()
                        # Check if operation succeeded (no authorization errors)
                        if 'errors' not in data:
                            self.vulnerabilities.append({
                                'category': 'GraphQL Authorization',
                                'risk_level': 'High',
                                'title': 'Potential Authorization Bypass',
                                'description': 'Sensitive operation executed without proper authorization checks',
                                'location': endpoint['url'],
                                'evidence': f'Query: {json.dumps(query)[:150]}...',
                                'recommendation': 'Implement proper authorization checks for all operations and fields'
                            })
                        # Even if there are errors, check if we got partial data
                        elif 'data' in data and data['data'] is not None:
                            self.vulnerabilities.append({
                                'category': 'GraphQL Authorization', 
                                'risk_level': 'Medium',
                                'title': 'Partial Data Exposure',
                                'description': 'Sensitive query returned partial data despite errors',
                                'location': endpoint['url'],
                                'evidence': 'Partial data returned for sensitive query',
                                'recommendation': 'Ensure failed authorization prevents any data exposure'
                            })
                    except:
                        pass
                
                time.sleep(0.1)  # Be nice to the server

    def calculate_security_score(self):
        """Calculate security score based on vulnerabilities found"""
        base_score = 100
        
        # Deduct points based on vulnerability severity
        for vulnerability in self.vulnerabilities:
            risk_level = vulnerability.get('risk_level', 'Info')
            if risk_level == 'High':
                base_score -= 10
            elif risk_level == 'Medium':
                base_score -= 5
            elif risk_level == 'Low':
                base_score -= 2
        
        return max(0, base_score)