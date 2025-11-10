# scanners/deep/jwt_security_scanner.py - UPDATED VERSION

import re
import jwt
import hashlib
import hmac
from ..base_scanner import SecurityScanner

class JWTSecurityScanner(SecurityScanner):
    """Enhanced JWT security scanner with cryptographic testing"""
    
    def run_scan(self):
        """Run JWT security scan"""
        try:
            print(f"[*] Starting JWT security scan for: {self.target_url}")
            self.update_progress(10, "🔑 Starting JWT security scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test JWT security
            self.update_progress(50, "🔍 Testing JWT implementations...")
            self.test_jwt_security()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # NEW: Test for weak secrets
            self.update_progress(70, "🔐 Testing for weak JWT secrets...")
            self.test_weak_jwt_secrets()
            
            # Finalize
            self.update_progress(95, "📊 Generating JWT security report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ JWT security scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] JWT security scan error: {e}")
            return self._build_results('error', error_message=str(e))

    def test_jwt_security(self):
        """Test JWT security vulnerabilities"""
        try:
            # Check for JWT tokens in responses and local storage (conceptual)
            success, response = self.safe_request('GET', self.target_url)
            if success:
                # Look for JWT patterns in response
                jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
                jwt_tokens = re.findall(jwt_pattern, response.text)
                
                if jwt_tokens:
                    self.vulnerabilities.append({
                        'category': 'JWT Security',
                        'risk_level': 'Medium',
                        'title': 'JWT Tokens Found in Response',
                        'description': 'JWT tokens detected in HTTP responses',
                        'location': self.target_url,
                        'evidence': f'Found {len(jwt_tokens)} JWT token(s) in response',
                        'recommendation': 'Avoid exposing JWT tokens in responses; use HttpOnly cookies for storage'
                    })
                    
                    # Test for weak JWT algorithms
                    self._test_jwt_tokens(jwt_tokens)
            
        except Exception as e:
            print(f"[-] JWT security test error: {e}")

    def _test_jwt_tokens(self, jwt_tokens):
        """Test JWT tokens for common vulnerabilities"""
        for token in jwt_tokens[:3]:  # Test first 3 tokens
            try:
                # Try to decode without verification (testing for none algorithm)
                decoded = jwt.decode(token, options={"verify_signature": False})
                
                # Check for weak algorithms
                header = jwt.get_unverified_header(token)
                if header.get('alg') == 'none':
                    self.vulnerabilities.append({
                        'category': 'JWT Security',
                        'risk_level': 'High',
                        'title': 'JWT None Algorithm Vulnerability',
                        'description': 'JWT token uses "none" algorithm which provides no security',
                        'location': self.target_url,
                        'evidence': f'JWT token uses alg: none',
                        'recommendation': 'Reject JWT tokens with "none" algorithm and use strong algorithms like RS256'
                    })
                
                # Check for HS256 with weak secrets
                if header.get('alg') == 'HS256':
                    self.vulnerabilities.append({
                        'category': 'JWT Security',
                        'risk_level': 'Medium',
                        'title': 'JWT Using Symmetric Algorithm',
                        'description': 'JWT token uses HS256 which may be vulnerable to brute force if weak secret',
                        'location': self.target_url,
                        'evidence': f'JWT token uses alg: HS256',
                        'recommendation': 'Consider using asymmetric algorithms like RS256 for better security'
                    })
                
                # Check for sensitive data in payload
                sensitive_fields = ['password', 'secret', 'private_key', 'api_key', 'social_security', 'credit_card']
                for field in sensitive_fields:
                    if field in decoded:
                        self.vulnerabilities.append({
                            'category': 'JWT Security',
                            'risk_level': 'Medium',
                            'title': 'Sensitive Data in JWT Payload',
                            'description': f'Sensitive field "{field}" found in JWT payload',
                            'location': self.target_url,
                            'evidence': f'JWT payload contains sensitive field: {field}',
                            'recommendation': 'Avoid storing sensitive data in JWT payloads'
                        })
                
                # NEW: Check for missing expiration
                if 'exp' not in decoded:
                    self.vulnerabilities.append({
                        'category': 'JWT Security',
                        'risk_level': 'Medium',
                        'title': 'JWT Missing Expiration Claim',
                        'description': 'JWT token does not have expiration time (exp claim)',
                        'location': self.target_url,
                        'evidence': 'JWT payload missing exp field',
                        'recommendation': 'Always include expiration time in JWT tokens'
                    })
                
                # NEW: Check for weak issuer/audience
                if 'iss' in decoded and decoded['iss'] in ['test', 'localhost', 'example']:
                    self.vulnerabilities.append({
                        'category': 'JWT Security',
                        'risk_level': 'Low',
                        'title': 'Weak JWT Issuer Claim',
                        'description': f'JWT token uses weak issuer: {decoded["iss"]}',
                        'location': self.target_url,
                        'evidence': f'JWT issuer: {decoded["iss"]}',
                        'recommendation': 'Use proper domain names for JWT issuer claims'
                    })
                        
            except Exception as e:
                # Token decoding failed, which might be expected
                continue

    def test_weak_jwt_secrets(self):
        """NEW: Test for weak JWT secrets using common passwords"""
        try:
            # Common weak secrets to test
            weak_secrets = [
                'secret', 'password', '123456', 'admin', 'token',
                'key', 'jwt', 'test', 'debug', 'default',
                'changeme', 'master', 'root', 'access', 'security'
            ]
            
            success, response = self.safe_request('GET', self.target_url)
            if success:
                # Look for JWT tokens
                jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
                jwt_tokens = re.findall(jwt_pattern, response.text)
                
                for token in jwt_tokens[:2]:  # Test first 2 tokens
                    for secret in weak_secrets:
                        try:
                            # Try to decode with weak secret
                            decoded = jwt.decode(token, secret, algorithms=['HS256'])
                            
                            # If successful, weak secret found
                            self.vulnerabilities.append({
                                'category': 'JWT Security',
                                'risk_level': 'Critical',
                                'title': 'Weak JWT Secret Found',
                                'description': f'JWT token uses weak secret: {secret}',
                                'location': self.target_url,
                                'evidence': f'JWT decoded with weak secret: {secret}',
                                'recommendation': 'Use strong, randomly generated secrets for JWT signing'
                            })
                            break
                            
                        except jwt.InvalidSignatureError:
                            continue  # Try next secret
                        except Exception:
                            continue  # Other error, try next secret
                            
        except Exception as e:
            print(f"[-] Weak JWT secrets test error: {e}")