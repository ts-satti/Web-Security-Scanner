# scanners/__init__.py
"""
Security Scanner Modules
Standard Scanners: Basic OWASP Top 10 and individual scanners
Deep Scanners: Enhanced scanners with advanced payloads and new categories
"""

from .base_scanner import SecurityScanner
from .scanner_factory import ScannerFactory

# Make standard scanners available
from .standard.owasp_scanner import OWASPTop10Scanner
from .standard.xss_scanner import XSSScanner
from .standard.sqli_scanner import SQLIScanner
from .standard.csrf_scanner import CSRFScanner
from .standard.headers_scanner import HeadersScanner
from .standard.info_disclosure_scanner import InfoDisclosureScanner
from .standard.port_scanner import PortScanner

# Make deep scanners available  
from .deep.deep_scanner import DeepScanner
from .deep.enhanced_xss_scanner import EnhancedXSSScanner
from .deep.enhanced_sqli_scanner import EnhancedSQLIScanner
from .deep.api_security_scanner import APISecurityScanner
from .deep.jwt_security_scanner import JWTSecurityScanner
from .deep.business_logic_scanner import BusinessLogicScanner

__all__ = [
    'SecurityScanner', 'ScannerFactory',
    'OWASPTop10Scanner', 'XSSScanner', 'SQLIScanner', 'CSRFScanner',
    'HeadersScanner', 'InfoDisclosureScanner', 'PortScanner',
    'DeepScanner', 'EnhancedXSSScanner', 'EnhancedSQLIScanner',
    'APISecurityScanner', 'JWTSecurityScanner', 'BusinessLogicScanner'
]