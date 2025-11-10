# scanners/deep/__init__.py
"""
Deep Security Scanners
Enhanced scanners with advanced payloads and new security categories
"""

from .deep_scanner import DeepScanner
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

__all__ = [
    'DeepScanner', 'EnhancedXSSScanner', 'EnhancedSQLIScanner',
    'EnhancedCSRFScanner', 'EnhancedHeadersScanner', 'EnhancedInfoDisclosureScanner',
    'APISecurityScanner', 'JWTSecurityScanner', 'BusinessLogicScanner',
    'WebSocketScanner', 'GraphQLSecurityScanner', 'FuzzTestingScanner',
    'BrokenAccessControlScanner', 'CryptographicFailuresScanner'
]