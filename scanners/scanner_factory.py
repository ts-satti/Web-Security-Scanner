# scanners/scanner_factory.py - UPDATED VERSION

from .standard.owasp_scanner import OWASPTop10Scanner
from .standard.xss_scanner import XSSScanner
from .standard.sqli_scanner import SQLIScanner
from .standard.csrf_scanner import CSRFScanner
from .standard.headers_scanner import HeadersScanner
from .standard.info_disclosure_scanner import InfoDisclosureScanner
from .standard.port_scanner import PortScanner

from .deep.deep_scanner import DeepScanner
from .deep.enhanced_xss_scanner import EnhancedXSSScanner
from .deep.enhanced_sqli_scanner import EnhancedSQLIScanner  # Updated
from .deep.enhanced_csrf_scanner import EnhancedCSRFScanner
from .deep.enhanced_headers_scanner import EnhancedHeadersScanner
from .deep.enhanced_info_disclosure_scanner import EnhancedInfoDisclosureScanner
from .deep.api_security_scanner import APISecurityScanner  # Updated
from .deep.jwt_security_scanner import JWTSecurityScanner  # Updated
from .deep.business_logic_scanner import BusinessLogicScanner  # Updated
from .deep.websocket_scanner import WebSocketScanner
from .deep.graphql_security_scanner import GraphQLSecurityScanner
from .deep.fuzz_testing_scanner import FuzzTestingScanner
from .deep.broken_access_control_scanner import BrokenAccessControlScanner
from .deep.cryptographic_failures_scanner import CryptographicFailuresScanner

class ScannerFactory:
    """Factory class for creating scanner instances"""
    
    @staticmethod
    def create_scanner(scan_type, target_url, scan_id, config=None):
        """
        Create appropriate scanner based on scan type
        """
        scanners = {
            # 🔒 Standard Scanners
            'owasp_top_10': OWASPTop10Scanner,
            'xss': XSSScanner,
            'sqli': SQLIScanner,
            'csrf': CSRFScanner,
            'headers': HeadersScanner,
            'info_disclosure': InfoDisclosureScanner,
            'port_scan': PortScanner,
            
            # 🚀 Deep Scanners (Individual) - NOW ENHANCED
            'enhanced_xss': EnhancedXSSScanner,
            'enhanced_sqli': EnhancedSQLIScanner,  # Now with blind SQLi
            'api_security': APISecurityScanner,  # Now with enhanced GraphQL
            'jwt_security': JWTSecurityScanner,  # Now with weak secret testing
            'business_logic': BusinessLogicScanner,  # Now with price manipulation
            'websocket': WebSocketScanner,
            'graphql': GraphQLSecurityScanner,
            'fuzz_testing': FuzzTestingScanner,
            'broken_access_control': BrokenAccessControlScanner,
            'cryptographic_failures': CryptographicFailuresScanner,
            
            # 🚀 DEEP Scanner (Orchestrator)
            'deep_scan': DeepScanner,
        }
        
        scanner_class = scanners.get(scan_type)
        if not scanner_class:
            # Default to OWASP scanner for unknown types
            scanner_class = OWASPTop10Scanner
        
        return scanner_class(target_url, scan_id, config)
    
    @staticmethod
    def get_available_scanners():
        """Get list of available scanner types organized by category"""
        return {
            '🔒 Standard Security Scanners': {
                'owasp_top_10': 'OWASP Top 10 Standard Scan',
                'xss': 'XSS Vulnerability Scan',
                'sqli': 'SQL Injection Scan',
                'csrf': 'CSRF Vulnerability Scan',
                'headers': 'Security Headers Scan',
                'info_disclosure': 'Information Disclosure Scan',
                'port_scan': 'Port Scanning',
            },
            '🚀 Enhanced Deep Scanners': {
                'enhanced_xss': 'Enhanced XSS Scan (Advanced Payloads)',
                'enhanced_sqli': 'Enhanced SQL Injection Scan + Blind SQLi',  # Updated
                'api_security': 'API Security Scan + GraphQL Testing',  # Updated
                'jwt_security': 'JWT Security Scan + Weak Secrets',  # Updated
                'business_logic': 'Business Logic Scan + Price Manipulation',  # Updated
                'websocket': 'WebSocket Security Scan',
                'graphql': 'GraphQL Security Scan',
                'broken_access_control': 'Broken Access Control Scan',
                'cryptographic_failures': 'Cryptographic Failures Scan',
                'fuzz_testing': 'Fuzz Testing',
            },
            '🚀 Ultimate Power Scanner': {
                'deep_scan': 'DEEP Security Scan (All Enhanced + Advanced)',
            }
        }