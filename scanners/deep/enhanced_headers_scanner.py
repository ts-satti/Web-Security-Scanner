# scanners/advanced/enhanced_headers_scanner.py
import time
import re
from urllib.parse import urljoin
from ..base_scanner import SecurityScanner

class EnhancedHeadersScanner(SecurityScanner):
    """Advanced security headers scanner"""
    
    def run_scan(self):
        """Run comprehensive security headers scan"""
        try:
            print(f"[*] Starting Advanced Security Headers scan for: {self.target_url}")
            self.update_progress(10, "🚀 Initializing advanced headers scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 1: Basic security headers
            self.update_progress(20, "📋 Checking basic security headers...")
            self.test_basic_security_headers()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 2: Advanced CSP analysis
            self.update_progress(35, "🛡️ Analyzing Content Security Policy...")
            self.analyze_content_security_policy()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 3: HSTS deep analysis
            self.update_progress(50, "🔒 Analyzing HSTS configuration...")
            self.analyze_hsts_configuration()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 4: Cookie security analysis
            self.update_progress(65, "🍪 Analyzing cookie security headers...")
            self.analyze_cookie_security()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 5: Advanced header analysis
            self.update_progress(80, "🔍 Performing advanced header analysis...")
            self.perform_advanced_header_analysis()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Phase 6: Cross-origin policies
            self.update_progress(90, "🌐 Checking cross-origin policies...")
            self.check_cross_origin_policies()
            
            # Finalize
            self.update_progress(95, "📊 Generating comprehensive headers report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Advanced headers scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Advanced headers scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def test_basic_security_headers(self):
        """Comprehensive basic security headers testing"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            headers = response.headers
            security_headers = {
                'X-Frame-Options': {
                    'description': 'Prevents clickjacking attacks',
                    'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN',
                    'risk_level': 'Medium'
                },
                'X-Content-Type-Options': {
                    'description': 'Prevents MIME sniffing attacks',
                    'recommendation': 'Set X-Content-Type-Options to nosniff',
                    'risk_level': 'Medium'
                },
                'Content-Security-Policy': {
                    'description': 'Prevents XSS and other code injection attacks',
                    'recommendation': 'Implement a strong Content Security Policy',
                    'risk_level': 'High'
                },
                'Strict-Transport-Security': {
                    'description': 'Enforces HTTPS connections',
                    'recommendation': 'Set Strict-Transport-Security with appropriate max-age',
                    'risk_level': 'High'
                },
                'X-XSS-Protection': {
                    'description': 'Enables browser XSS protection (legacy)',
                    'recommendation': 'Use Content-Security-Policy instead for modern protection',
                    'risk_level': 'Low'
                },
                'Referrer-Policy': {
                    'description': 'Controls referrer information in requests',
                    'recommendation': 'Set Referrer-Policy to strict-origin-when-cross-origin or stricter',
                    'risk_level': 'Low'
                },
                'Permissions-Policy': {
                    'description': 'Controls browser features and APIs',
                    'recommendation': 'Implement Permissions-Policy for enhanced security',
                    'risk_level': 'Medium'
                },
                'Cross-Origin-Embedder-Policy': {
                    'description': 'Prevents a document from loading cross-origin resources',
                    'recommendation': 'Set Cross-Origin-Embedder-Policy to require-corp',
                    'risk_level': 'Medium'
                },
                'Cross-Origin-Opener-Policy': {
                    'description': 'Isates browsing context group',
                    'recommendation': 'Set Cross-Origin-Opener-Policy to same-origin',
                    'risk_level': 'Medium'
                },
                'Cross-Origin-Resource-Policy': {
                    'description': 'Prevents other domains from reading the resource',
                    'recommendation': 'Set Cross-Origin-Resource-Policy to same-origin',
                    'risk_level': 'Medium'
                }
            }
            
            for header, info in security_headers.items():
                if self.check_stop_flag():
                    return
                self.check_pause_flag()
                
                if header not in headers:
                    self.vulnerabilities.append({
                        'category': 'Security Headers',
                        'risk_level': info['risk_level'],
                        'title': f'Missing Security Header: {header}',
                        'description': info['description'],
                        'location': self.target_url,
                        'evidence': f'{header} header not present in response',
                        'recommendation': info['recommendation']
                    })
                else:
                    # Validate header values
                    self._validate_header_value(header, headers[header])
            
            # Check for deprecated headers
            self._check_deprecated_headers(headers)
            
            # Check for information disclosure headers
            self._check_information_disclosure_headers(headers)
                        
        except Exception as e:
            print(f"[-] Basic security headers test error: {e}")
    
    def analyze_content_security_policy(self):
        """Deep analysis of Content Security Policy"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            csp_header = response.headers.get('Content-Security-Policy', '')
            csp_report_only = response.headers.get('Content-Security-Policy-Report-Only', '')
            
            if not csp_header and not csp_report_only:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'High',
                    'title': 'Missing Content Security Policy',
                    'description': 'No CSP header present to prevent XSS attacks',
                    'location': self.target_url,
                    'evidence': 'Content-Security-Policy header missing',
                    'recommendation': 'Implement a strong Content Security Policy with default-src, script-src, and object-src directives'
                })
                return
            
            # Analyze main CSP
            if csp_header:
                self._analyze_csp_policy(csp_header, 'Content-Security-Policy')
            
            # Analyze report-only CSP
            if csp_report_only:
                self._analyze_csp_policy(csp_report_only, 'Content-Security-Policy-Report-Only', is_report_only=True)
            
            # Check for CSP implementation best practices
            self._check_csp_best_practices(csp_header, csp_report_only)
            
        except Exception as e:
            print(f"[-] CSP analysis error: {e}")
    
    def analyze_hsts_configuration(self):
        """Comprehensive HSTS analysis"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            if not hsts_header:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'High',
                    'title': 'Missing HSTS Header',
                    'description': 'No HSTS header to enforce HTTPS connections',
                    'location': self.target_url,
                    'evidence': 'Strict-Transport-Security header missing',
                    'recommendation': 'Implement HSTS with max-age of at least 31536000 (1 year) and includeSubDomains'
                })
                return
            
            # Parse HSTS directives
            hsts_directives = self._parse_hsts_directives(hsts_header)
            
            # Check max-age
            max_age = hsts_directives.get('max-age')
            if not max_age or int(max_age) < 31536000:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Medium',
                    'title': 'Weak HSTS max-age',
                    'description': 'HSTS max-age is too short',
                    'location': self.target_url,
                    'evidence': f'HSTS max-age: {max_age if max_age else "missing"}',
                    'recommendation': 'Set HSTS max-age to at least 31536000 (1 year)'
                })
            
            # Check includeSubDomains
            if 'includeSubDomains' not in hsts_directives:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Medium',
                    'title': 'HSTS Missing includeSubDomains',
                    'description': 'HSTS not applied to subdomains',
                    'location': self.target_url,
                    'evidence': 'includeSubDomains directive missing',
                    'recommendation': 'Add includeSubDomains directive to protect all subdomains'
                })
            
            # Check preload
            if 'preload' not in hsts_directives:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Low',
                    'title': 'HSTS Not Preload Ready',
                    'description': 'HSTS not configured for preload list',
                    'location': self.target_url,
                    'evidence': 'preload directive missing',
                    'recommendation': 'Consider adding preload directive after ensuring all subdomains support HTTPS'
                })
            
            # Test HSTS preload eligibility
            self._test_hsts_preload_eligibility(hsts_directives)
            
        except Exception as e:
            print(f"[-] HSTS analysis error: {e}")
    
    def analyze_cookie_security(self):
        """Analyze cookie security attributes"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            set_cookie_headers = response.headers.getlist('Set-Cookie')
            
            for cookie_header in set_cookie_headers:
                if self.check_stop_flag():
                    return
                self.check_pause_flag()
                
                cookie_analysis = self._analyze_cookie_header(cookie_header)
                
                # Report security issues
                for issue in cookie_analysis.get('security_issues', []):
                    self.vulnerabilities.append({
                        'category': 'Cookie Security',
                        'risk_level': issue['risk_level'],
                        'title': issue['title'],
                        'description': issue['description'],
                        'location': self.target_url,
                        'evidence': issue['evidence'],
                        'recommendation': issue['recommendation']
                    })
            
            # Check for __Host- and __Secure- prefix usage
            self._check_cookie_prefixes(set_cookie_headers)
            
        except Exception as e:
            print(f"[-] Cookie security analysis error: {e}")
    
    def perform_advanced_header_analysis(self):
        """Perform advanced header security analysis"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            headers = response.headers
            
            # Check for cache control headers
            self._check_cache_control_headers(headers)
            
            # Check for feature policy / permissions policy
            self._check_feature_policies(headers)
            
            # Check for security header conflicts
            self._check_header_conflicts(headers)
            
            # Check for custom security headers
            self._check_custom_security_headers(headers)
            
            # Test header injection vulnerabilities
            self._test_header_injection()
            
        except Exception as e:
            print(f"[-] Advanced header analysis error: {e}")
    
    def check_cross_origin_policies(self):
        """Check cross-origin related security headers"""
        try:
            success, response = self.safe_request('GET', self.target_url)
            if not success:
                return
            
            headers = response.headers
            
            # Check COEP, COOP, CORP
            self._check_cross_origin_headers(headers)
            
            # Check CORS headers
            self._check_cors_headers()
            
            # Check OWASP recommended headers
            self._check_owasp_recommended_headers(headers)
            
        except Exception as e:
            print(f"[-] Cross-origin policies check error: {e}")
    
    def _validate_header_value(self, header, value):
        """Validate security header values for common misconfigurations"""
        value_lower = value.lower()
        
        if header == 'X-Frame-Options':
            if 'deny' not in value_lower and 'sameorigin' not in value_lower:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Medium',
                    'title': f'Weak {header} Configuration',
                    'description': f'{header} has invalid or weak value',
                    'location': self.target_url,
                    'evidence': f'{header} set to: {value}',
                    'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
                })
            elif 'allow-from' in value_lower:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Low',
                    'title': f'Deprecated {header} Directive',
                    'description': f'{header} uses deprecated allow-from directive',
                    'location': self.target_url,
                    'evidence': f'{header} uses allow-from directive',
                    'recommendation': 'Use Content-Security-Policy frame-ancestors directive instead'
                })
        
        elif header == 'X-Content-Type-Options' and 'nosniff' not in value_lower:
            self.vulnerabilities.append({
                'category': 'Security Headers',
                'risk_level': 'Medium',
                'title': f'Weak {header} Configuration',
                'description': f'{header} should be set to nosniff',
                'location': self.target_url,
                'evidence': f'{header} set to: {value}',
                'recommendation': 'Set X-Content-Type-Options to nosniff'
            })
        
        elif header == 'X-XSS-Protection':
            if '0' in value_lower:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Low',
                    'title': f'{header} Disabled',
                    'description': f'{header} is explicitly disabled',
                    'location': self.target_url,
                    'evidence': f'{header} set to: {value}',
                    'recommendation': 'Use Content-Security-Policy for modern XSS protection instead'
                })
            elif '1; mode=block' not in value_lower:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Low',
                    'title': f'Weak {header} Configuration',
                    'description': f'{header} not configured to block rendering',
                    'location': self.target_url,
                    'evidence': f'{header} set to: {value}',
                    'recommendation': 'Set X-XSS-Protection to 1; mode=block or use CSP'
                })
        
        elif header == 'Referrer-Policy':
            weak_policies = ['no-referrer-when-downgrade', 'origin-when-cross-origin', 'unsafe-url']
            if value_lower in weak_policies:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Low',
                    'title': f'Weak {header} Configuration',
                    'description': f'{header} uses a less strict policy',
                    'location': self.target_url,
                    'evidence': f'{header} set to: {value}',
                    'recommendation': 'Consider using stricter policies like strict-origin-when-cross-origin or same-origin'
                })
    
    def _check_deprecated_headers(self, headers):
        """Check for deprecated security headers"""
        deprecated_headers = {
            'Public-Key-Pins': {
                'description': 'HTTP Public Key Pinning is deprecated',
                'recommendation': 'Use Certificate Transparency and Expect-CT instead'
            },
            'X-WebKit-CSP': {
                'description': 'WebKit-specific CSP header is deprecated',
                'recommendation': 'Use standard Content-Security-Policy header'
            },
            'X-Content-Security-Policy': {
                'description': 'Old Firefox CSP header is deprecated',
                'recommendation': 'Use standard Content-Security-Policy header'
            }
        }
        
        for header, info in deprecated_headers.items():
            if header in headers:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Low',
                    'title': f'Deprecated Header: {header}',
                    'description': info['description'],
                    'location': self.target_url,
                    'evidence': f'Deprecated header {header} found',
                    'recommendation': info['recommendation']
                })
    
    def _check_information_disclosure_headers(self, headers):
        """Check headers that disclose server information"""
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        
        for header in info_headers:
            if header in headers:
                self.vulnerabilities.append({
                    'category': 'Information Disclosure',
                    'risk_level': 'Low',
                    'title': f'Information Disclosure: {header}',
                    'description': f'{header} header reveals server information',
                    'location': self.target_url,
                    'evidence': f'{header}: {headers[header]}',
                    'recommendation': 'Remove or obfuscate server information headers'
                })
    
    def _analyze_csp_policy(self, csp_value, header_name, is_report_only=False):
        """Analyze CSP policy for weaknesses"""
        directives = self._parse_csp_directives(csp_value)
        
        # Check for missing essential directives
        essential_directives = ['default-src', 'script-src', 'object-src']
        for directive in essential_directives:
            if directive not in directives:
                suffix = ' (Report-Only)' if is_report_only else ''
                self.vulnerabilities.append({
                    'category': 'Content Security Policy',
                    'risk_level': 'High',
                    'title': f'Missing CSP Directive: {directive}{suffix}',
                    'description': f'CSP missing essential {directive} directive',
                    'location': self.target_url,
                    'evidence': f'{header_name} missing {directive} directive',
                    'recommendation': f'Add {directive} directive to CSP'
                })
        
        # Check for unsafe directives
        unsafe_patterns = ["'unsafe-inline'", "'unsafe-eval'", "data:", "blob:", "*"]
        for directive, values in directives.items():
            for pattern in unsafe_patterns:
                if pattern in values:
                    suffix = ' (Report-Only)' if is_report_only else ''
                    risk_level = 'High' if pattern in ["'unsafe-eval'", "*"] else 'Medium'
                    self.vulnerabilities.append({
                        'category': 'Content Security Policy',
                        'risk_level': risk_level,
                        'title': f'Unsafe CSP Directive: {directive}{suffix}',
                        'description': f'CSP {directive} contains unsafe value: {pattern}',
                        'location': self.target_url,
                        'evidence': f'{directive} contains {pattern}',
                        'recommendation': f'Remove {pattern} from {directive} and use nonces/hashes instead'
                    })
        
        # Check for missing base-uri
        if 'base-uri' not in directives:
            suffix = ' (Report-Only)' if is_report_only else ''
            self.vulnerabilities.append({
                'category': 'Content Security Policy',
                'risk_level': 'Medium',
                'title': f'Missing CSP base-uri Directive{suffix}',
                'description': 'CSP missing base-uri directive against base tag injection',
                'location': self.target_url,
                'evidence': 'base-uri directive missing',
                'recommendation': 'Add base-uri directive to prevent base tag injection attacks'
            })
    
    def _parse_csp_directives(self, csp_value):
        """Parse CSP directives into a dictionary"""
        directives = {}
        for directive in csp_value.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            if ' ' in directive:
                name, values = directive.split(' ', 1)
                directives[name.strip()] = values.strip()
            else:
                directives[directive] = ''
        return directives
    
    def _parse_hsts_directives(self, hsts_value):
        """Parse HSTS directives into a dictionary"""
        directives = {}
        for part in hsts_value.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                directives[key.strip().lower()] = value.strip()
            else:
                directives[part.lower()] = True
        return directives
    
    def _check_csp_best_practices(self, csp_header, csp_report_only):
        """Check CSP implementation best practices"""
        # Check if using report-only without enforcement
        if csp_report_only and not csp_header:
            self.vulnerabilities.append({
                'category': 'Content Security Policy',
                'risk_level': 'Low',
                'title': 'CSP Report-Only Without Enforcement',
                'description': 'CSP is only in report-only mode without enforcement policy',
                'location': self.target_url,
                'evidence': 'Content-Security-Policy-Report-Only present but Content-Security-Policy missing',
                'recommendation': 'Implement an enforced CSP policy alongside report-only'
            })
        
        # Check for report-uri / report-to usage
        if csp_header and 'report-uri' not in csp_header.lower() and 'report-to' not in csp_header.lower():
            self.vulnerabilities.append({
                'category': 'Content Security Policy',
                'risk_level': 'Low',
                'title': 'CSP Missing Reporting',
                'description': 'CSP missing report-uri or report-to directive',
                'location': self.target_url,
                'evidence': 'No reporting directive in CSP',
                'recommendation': 'Add report-uri or report-to directive to monitor CSP violations'
            })
    
    def _test_hsts_preload_eligibility(self, hsts_directives):
        """Test if HSTS configuration is eligible for preload"""
        max_age = hsts_directives.get('max-age')
        has_include_subdomains = 'includesubdomains' in hsts_directives
        has_preload = 'preload' in hsts_directives
        
        if has_preload and (not max_age or int(max_age) < 31536000 or not has_include_subdomains):
            self.vulnerabilities.append({
                'category': 'Security Headers',
                'risk_level': 'Medium',
                'title': 'Invalid HSTS Preload Configuration',
                'description': 'HSTS preload directive present but configuration invalid for preloading',
                'location': self.target_url,
                'evidence': f'max-age: {max_age}, includeSubDomains: {has_include_subdomains}',
                'recommendation': 'For preload eligibility, set max-age to at least 31536000 and include includeSubDomains'
            })
    
    def _analyze_cookie_header(self, cookie_header):
        """Analyze Set-Cookie header for security attributes"""
        analysis = {
            'name': '',
            'security_issues': []
        }
        
        # Extract cookie name and attributes
        parts = cookie_header.split(';')
        cookie_name = parts[0].split('=')[0] if '=' in parts[0] else parts[0]
        analysis['name'] = cookie_name
        
        attributes = {}
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                attributes[key.strip().lower()] = value.strip()
            else:
                attributes[part.strip().lower()] = True
        
        # Check for security attributes
        if not attributes.get('secure'):
            analysis['security_issues'].append({
                'risk_level': 'High',
                'title': 'Cookie Missing Secure Flag',
                'description': f'Cookie "{cookie_name}" missing Secure flag',
                'evidence': 'Secure attribute not set',
                'recommendation': 'Set Secure flag for all cookies on HTTPS sites'
            })
        
        if not attributes.get('httponly'):
            analysis['security_issues'].append({
                'risk_level': 'High',
                'title': 'Cookie Missing HttpOnly Flag',
                'description': f'Cookie "{cookie_name}" missing HttpOnly flag',
                'evidence': 'HttpOnly attribute not set',
                'recommendation': 'Set HttpOnly flag to prevent client-side script access'
            })
        
        samesite = attributes.get('samesite')
        if not samesite:
            analysis['security_issues'].append({
                'risk_level': 'Medium',
                'title': 'Cookie Missing SameSite Attribute',
                'description': f'Cookie "{cookie_name}" missing SameSite attribute',
                'evidence': 'SameSite attribute not set',
                'recommendation': 'Set SameSite=Lax or Strict for CSRF protection'
            })
        elif samesite.lower() == 'none' and not attributes.get('secure'):
            analysis['security_issues'].append({
                'risk_level': 'High',
                'title': 'Insecure SameSite=None Cookie',
                'description': f'Cookie "{cookie_name}" has SameSite=None without Secure flag',
                'evidence': 'SameSite=None without Secure flag',
                'recommendation': 'Either set Secure flag or change SameSite to Lax/Strict'
            })
        
        return analysis
    
    def _check_cookie_prefixes(self, set_cookie_headers):
        """Check for secure cookie prefix usage"""
        secure_cookies = []
        host_cookies = []
        
        for header in set_cookie_headers:
            cookie_name = header.split('=')[0] if '=' in header else header
            if cookie_name.startswith('__Secure-'):
                secure_cookies.append(cookie_name)
            if cookie_name.startswith('__Host-'):
                host_cookies.append(cookie_name)
        
        if not secure_cookies and not host_cookies:
            self.vulnerabilities.append({
                'category': 'Cookie Security',
                'risk_level': 'Low',
                'title': 'Missing Secure Cookie Prefixes',
                'description': 'No cookies using __Secure- or __Host- prefixes',
                'location': self.target_url,
                'evidence': 'No secure cookie prefixes found',
                'recommendation': 'Consider using __Secure- and __Host- prefixes for additional cookie security'
            })
    
    def _check_cache_control_headers(self, headers):
        """Check cache control headers for sensitive content"""
        cache_control = headers.get('Cache-Control', '').lower()
        pragma = headers.get('Pragma', '').lower()
        expires = headers.get('Expires', '')
        
        sensitive_paths = ['/api/', '/admin/', '/login', '/account', '/user', '/profile']
        current_path = self.target_url.lower()
        
        # Check if current path might contain sensitive information
        is_sensitive = any(path in current_path for path in sensitive_paths)
        
        if is_sensitive:
            if 'no-cache' not in cache_control and 'no-store' not in cache_control:
                self.vulnerabilities.append({
                    'category': 'Cache Security',
                    'risk_level': 'Medium',
                    'title': 'Sensitive Content Caching',
                    'description': 'Sensitive content may be cached by browsers/proxies',
                    'location': self.target_url,
                    'evidence': f'Cache-Control: {headers.get("Cache-Control", "missing")}',
                    'recommendation': 'Set Cache-Control: no-store, no-cache for sensitive content'
                })
    
    def _check_feature_policies(self, headers):
        """Check Feature-Policy / Permissions-Policy headers"""
        feature_policy = headers.get('Feature-Policy', '')
        permissions_policy = headers.get('Permissions-Policy', '')
        
        if not feature_policy and not permissions_policy:
            self.vulnerabilities.append({
                'category': 'Security Headers',
                'risk_level': 'Medium',
                'title': 'Missing Feature Policy',
                'description': 'No Feature-Policy or Permissions-Policy header present',
                'location': self.target_url,
                'evidence': 'Both Feature-Policy and Permissions-Policy headers missing',
                'recommendation': 'Implement Permissions-Policy to control browser features'
            })
            return
        
        # Check for dangerous features
        dangerous_features = ['camera', 'microphone', 'geolocation', 'payment']
        policy_used = permissions_policy if permissions_policy else feature_policy
        
        for feature in dangerous_features:
            if feature in policy_used.lower():
                # Check if feature is allowed globally
                if f"{feature}=*" in policy_used or f"{feature} *" in policy_used:
                    self.vulnerabilities.append({
                        'category': 'Security Headers',
                        'risk_level': 'Medium',
                        'title': f'Overly Permissive {feature} Policy',
                        'description': f'Dangerous feature {feature} allowed from all origins',
                        'location': self.target_url,
                        'evidence': f'{feature} allowed globally in policy',
                        'recommendation': f'Restrict {feature} to specific origins or disable entirely'
                    })
    
    def _check_header_conflicts(self, headers):
        """Check for conflicting security headers"""
        # Check X-Frame-Options vs CSP frame-ancestors
        x_frame_options = headers.get('X-Frame-Options')
        csp = headers.get('Content-Security-Policy', '')
        
        if x_frame_options and 'frame-ancestors' in csp:
            self.vulnerabilities.append({
                'category': 'Security Headers',
                'risk_level': 'Low',
                'title': 'Conflicting Frame Protection Headers',
                'description': 'Both X-Frame-Options and CSP frame-ancestors present',
                'location': self.target_url,
                'evidence': 'X-Frame-Options and CSP frame-ancestors both set',
                'recommendation': 'Use CSP frame-ancestors directive instead of X-Frame-Options for modern protection'
            })
    
    def _check_custom_security_headers(self, headers):
        """Check for custom security headers"""
        custom_headers = [
            'X-Custom-Security-Header',
            'X-Security-Header',
            'X-Content-Security',
            'X-Web-Security'
        ]
        
        for header in custom_headers:
            if header in headers:
                self.vulnerabilities.append({
                    'category': 'Security Headers',
                    'risk_level': 'Info',
                    'title': f'Custom Security Header: {header}',
                    'description': f'Custom security header {header} detected',
                    'location': self.target_url,
                    'evidence': f'{header}: {headers[header]}',
                    'recommendation': 'Ensure custom headers provide actual security value'
                })
    
    def _test_header_injection(self):
        """Test for header injection vulnerabilities"""
        # Test CRLF injection in redirects
        test_paths = [
            '/%0D%0ASet-Cookie:malicious=injected',
            '/%0D%0AX-Forwarded-For:127.0.0.1',
            '/%0D%0AX-Custom-Header:injected'
        ]
        
        for test_path in test_paths:
            if self.check_stop_flag():
                return
            
            test_url = urljoin(self.target_url, test_path)
            success, response = self.safe_request('GET', test_url)
            
            if success:
                # Check if our injected headers appear in response
                for header, value in response.headers.items():
                    if 'malicious' in header.lower() or 'malicious' in value.lower():
                        self.vulnerabilities.append({
                            'category': 'Header Injection',
                            'risk_level': 'High',
                            'title': 'CRLF Header Injection Vulnerability',
                            'description': 'Application vulnerable to CRLF header injection',
                            'location': test_url,
                            'evidence': f'Injected header found in response: {header}: {value}',
                            'recommendation': 'Sanitize user input and encode CRLF characters in URLs'
                        })
                        break
    
    def _check_cross_origin_headers(self, headers):
        """Check cross-origin isolation headers"""
        coep = headers.get('Cross-Origin-Embedder-Policy', '')
        coop = headers.get('Cross-Origin-Opener-Policy', '')
        corp = headers.get('Cross-Origin-Resource-Policy', '')
        
        if not coep:
            self.vulnerabilities.append({
                'category': 'Security Headers',
                'risk_level': 'Low',
                'title': 'Missing Cross-Origin-Embedder-Policy',
                'description': 'COEP header not present for cross-origin isolation',
                'location': self.target_url,
                'evidence': 'Cross-Origin-Embedder-Policy header missing',
                'recommendation': 'Set Cross-Origin-Embedder-Policy to require-corp for enhanced security'
            })
        
        if not coop:
            self.vulnerabilities.append({
                'category': 'Security Headers',
                'risk_level': 'Low',
                'title': 'Missing Cross-Origin-Opener-Policy',
                'description': 'COOP header not present for cross-origin isolation',
                'location': self.target_url,
                'evidence': 'Cross-Origin-Opener-Policy header missing',
                'recommendation': 'Set Cross-Origin-Opener-Policy to same-origin for enhanced security'
            })
    
    def _check_cors_headers(self):
        """Check CORS headers configuration"""
        # Test CORS with different origins
        test_origins = [
            'https://evil.com',
            'http://attacker.local',
            'null'
        ]
        
        for origin in test_origins:
            if self.check_stop_flag():
                return
            
            headers = {'Origin': origin}
            success, response = self.safe_request('OPTIONS', self.target_url, headers=headers)
            
            if success:
                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                if acao == origin and acac == 'true':
                    self.vulnerabilities.append({
                        'category': 'CORS Security',
                        'risk_level': 'High',
                        'title': 'Overly Permissive CORS',
                        'description': f'CORS allows arbitrary origin {origin} with credentials',
                        'location': self.target_url,
                        'evidence': f'Access-Control-Allow-Origin: {acao} with Access-Control-Allow-Credentials: true',
                        'recommendation': 'Restrict CORS origins to trusted domains only'
                    })
                elif acao == '*':
                    self.vulnerabilities.append({
                        'category': 'CORS Security',
                        'risk_level': 'Medium',
                        'title': 'Wildcard CORS Origin',
                        'description': 'CORS allows any origin with wildcard',
                        'location': self.target_url,
                        'evidence': 'Access-Control-Allow-Origin: *',
                        'recommendation': 'Avoid using wildcard origins, especially with credentials'
                    })
    
    def _check_owasp_recommended_headers(self, headers):
        """Check OWASP recommended security headers"""
        owasp_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'Content-Security-Policy': 'present',
            'Strict-Transport-Security': 'present',
            'Referrer-Policy': 'present'
        }
        
        missing_owasp = []
        for header, expected in owasp_headers.items():
            if header not in headers:
                missing_owasp.append(header)
        
        if missing_owasp:
            self.vulnerabilities.append({
                'category': 'Security Headers',
                'risk_level': 'Medium',
                'title': 'Missing OWASP Recommended Headers',
                'description': 'Missing headers recommended by OWASP security guidelines',
                'location': self.target_url,
                'evidence': f'Missing headers: {", ".join(missing_owasp)}',
                'recommendation': 'Implement all OWASP recommended security headers'
            })