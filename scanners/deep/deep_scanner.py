# scanners/deep/deep_scanner.py
import time
from ..standard.owasp_scanner import OWASPTop10Scanner
from .enhanced_xss_scanner import EnhancedXSSScanner
from .enhanced_sqli_scanner import EnhancedSQLIScanner
from .enhanced_csrf_scanner import EnhancedCSRFScanner
from .enhanced_headers_scanner import EnhancedHeadersScanner
from .enhanced_info_disclosure_scanner import EnhancedInfoDisclosureScanner
from .api_security_scanner import APISecurityScanner
from .jwt_security_scanner import JWTSecurityScanner
from .business_logic_scanner import BusinessLogicScanner
from .websocket_scanner import WebSocketScanner
from .graphql_security_scanner import GraphQLSecurityScanner
from .fuzz_testing_scanner import FuzzTestingScanner
from .broken_access_control_scanner import BrokenAccessControlScanner
from .cryptographic_failures_scanner import CryptographicFailuresScanner
from ..standard.port_scanner import PortScanner

class DeepScanner(OWASPTop10Scanner):
    """🚀 DEEP Security Scanner - Ultimate comprehensive security testing"""
    
    def __init__(self, target_url, scan_id, config=None):
        super().__init__(target_url, scan_id, config)
        self.scanners = self._initialize_all_scanners()
    
    def _initialize_all_scanners(self):
        """Initialize all enhanced and advanced scanners"""
        scanner_config = {
            'REQUEST_TIMEOUT': self.config.get('REQUEST_TIMEOUT', 10),
            'REQUEST_DELAY': self.config.get('REQUEST_DELAY', 0.5),
            'MAX_WORKERS': self.config.get('MAX_WORKERS', 3)
        }

        module_definitions = [
            # Enhanced OWASP Foundation
            ('Enhanced XSS Scanning', EnhancedXSSScanner),
            ('Enhanced SQL Injection', EnhancedSQLIScanner),
            ('Enhanced CSRF Protection', EnhancedCSRFScanner),
            ('Enhanced Security Headers', EnhancedHeadersScanner),
            ('Enhanced Information Disclosure', EnhancedInfoDisclosureScanner),

            # Advanced Category Scanners
            ('API Security Testing', APISecurityScanner),
            ('JWT Security Testing', JWTSecurityScanner),
            ('Business Logic Testing', BusinessLogicScanner),
            ('WebSocket Security', WebSocketScanner),
            ('GraphQL Security', GraphQLSecurityScanner),
            ('Broken Access Control', BrokenAccessControlScanner),
            ('Cryptographic Failures', CryptographicFailuresScanner),
            ('Fuzz Testing', FuzzTestingScanner),
            ('Port Scanning', PortScanner),
        ]

        scanners = []
        for module_name, scanner_cls in module_definitions:
            module_config = dict(scanner_config)
            scanner_instance = scanner_cls(self.target_url, self.scan_id, module_config)

            def aggregate_count(child=scanner_instance):
                try:
                    return len(self.vulnerabilities) + len(child.vulnerabilities)
                except Exception:
                    return len(self.vulnerabilities)

            scanner_instance.config['aggregate_vulnerability_provider'] = aggregate_count
            scanners.append((module_name, scanner_instance))

        return scanners
    
    def run_scan(self):
        """Run the ULTIMATE comprehensive security scan without progress percentage"""
        try:
            print(f"[*] Starting 🚀 DEEP security scan for: {self.target_url}")
            total_modules = len(self.scanners) or 1

            self.update_progress(
                "🚀 Starting ultimate comprehensive security scan...",
                f"Preparing {total_modules} advanced modules",
                progress_value=0
            )
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Check if paused before starting
            self.check_pause_flag()
        
            # Run all scanners in sequence while tracking overall progress
            for idx, (scanner_name, scanner) in enumerate(self.scanners, start=1):
                if self.check_stop_flag():
                    return self._build_results('stopped')
                
                # Check if paused and wait
                self.check_pause_flag()

                overall_progress = int(((idx - 1) / total_modules) * 100)
                self.update_progress(
                    f'Running {scanner_name}...',
                    f'Starting {scanner_name} module ({idx}/{total_modules})',
                    vulnerabilities_found=len(self.vulnerabilities),
                    progress_value=overall_progress
                )
                print(f"[*] Deep Scanner: Running {scanner_name}")
                
                try:
                    # Run the individual scanner
                    scanner_results = scanner.run_scan()
                    
                    # Collect vulnerabilities from scanner
                    if scanner_results and 'vulnerabilities' in scanner_results:
                        module_vulns = scanner_results['vulnerabilities']
                        if module_vulns:
                            before_count = len(self.vulnerabilities)
                            self.vulnerabilities.extend(module_vulns)
                            added_count = len(self.vulnerabilities) - before_count
                            print(f"[+] {scanner_name} found {added_count} vulnerabilities")
                            self.update_progress(
                                f'Running {scanner_name}...',
                                f'{scanner_name} findings increased to {len(self.vulnerabilities)} total',
                                vulnerabilities_found=len(self.vulnerabilities),
                                progress_value=overall_progress
                            )
                    
                except Exception as e:
                    print(f"[-] {scanner_name} scan error: {e}")
                    self.vulnerabilities.append({
                        'category': 'Scanner Error',
                        'risk_level': 'Info',
                        'title': f'{scanner_name} Scan Failed',
                        'description': f'{scanner_name} scanning encountered an error',
                        'location': self.target_url,
                        'evidence': f'Scanner error: {str(e)}',
                        'recommendation': 'Review scanner configuration and target accessibility'
                    })

                completed_progress = int((idx / total_modules) * 100)
                completed_progress = min(100, max(overall_progress, completed_progress))
                self.log_activity(f"✅ {scanner_name} module completed ({idx}/{total_modules})", 'success')
                self.update_progress(
                    f'Completed {scanner_name}',
                    f'Finished {scanner_name} module ({idx}/{total_modules}) — total findings: {len(self.vulnerabilities)}',
                    vulnerabilities_found=len(self.vulnerabilities),
                    progress_value=completed_progress
                )
                
                # Check pause during sleep between scanners
                if not self.check_stop_flag():
                    # Sleep in small increments and check pause flag
                    for _ in range(10):  # 1 second = 10 x 0.1 seconds
                        if self.check_stop_flag():
                            return self._build_results('stopped')
                        self.check_pause_flag()
                        time.sleep(0.1)
            
            # Calculate final security score
            security_score = max(0, 100 - (len(self.vulnerabilities) * 2))
            
            self.update_progress(
                '✅ 🚀 DEEP security scan completed!',
                'All advanced modules finished — compiling final report',
                vulnerabilities_found=len(self.vulnerabilities),
                progress_value=100
            )
            print(f"[+] 🚀 DEEP Scan Complete: Found {len(self.vulnerabilities)} total vulnerabilities")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Deep scan error: {e}")
            return self._build_results('error', error_message=str(e))