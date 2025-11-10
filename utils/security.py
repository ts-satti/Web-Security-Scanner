import re
import secrets
from urllib.parse import urlparse
import ipaddress

class SecurityUtils:
    """Security-related utility functions"""
    
    @staticmethod
    def generate_secure_token(length=32):
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def validate_url(target_url):
        """
        Comprehensive URL validation with security checks
        
        Returns: (is_valid, sanitized_url, error_message)
        """
        if not target_url:
            return False, None, "URL cannot be empty"
        
        # Add scheme if missing
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Basic URL validation
        try:
            parsed = urlparse(target_url)
            if not parsed.netloc:
                return False, None, "Invalid URL format - missing domain"
            
            # Check for basic URL structure
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', parsed.netloc):
                return False, None, "Invalid domain format"
                
        except Exception as e:
            return False, None, f"Invalid URL: {str(e)}"
        
        # Security checks - prevent SSRF and internal network scanning
        try:
            domain = parsed.netloc.split(':')[0]  # Remove port
            
            # Block internal IPs and localhost
            blocked_hosts = {
                'localhost', '127.0.0.1', '0.0.0.0', '::1',
                '169.254.169.254',  # AWS metadata service
            }
            
            if domain in blocked_hosts:
                return False, None, "Scanning internal hosts is not allowed"
            
            # Check if domain resolves to internal IP
            try:
                import socket
                ip = socket.gethostbyname(domain)
                ip_obj = ipaddress.ip_address(ip)
                
                if ip_obj.is_private or ip_obj.is_loopback:
                    return False, None, "Scanning internal IP addresses is not allowed"
                    
            except (socket.gaierror, ValueError):
                pass  # Could not resolve, but URL format is valid
                
        except Exception as e:
            return False, None, f"Security validation failed: {str(e)}"
        
        return True, target_url, "URL is valid"
    
    @staticmethod
    def sanitize_input(user_input, max_length=500):
        """Basic input sanitization"""
        if not user_input:
            return ""
        
        # Limit length
        user_input = user_input.strip()[:max_length]
        
        # Remove potentially dangerous characters for specific contexts
        dangerous_patterns = [
            r'<script.*?>.*?</script>',  # Script tags
            r'javascript:',              # JavaScript protocol
            r'vbscript:',                # VBScript protocol
            r'on\w+\s*=',                # Event handlers
        ]
        
        for pattern in dangerous_patterns:
            user_input = re.sub(pattern, '', user_input, flags=re.IGNORECASE)
        
        return user_input
    
    @staticmethod
    def is_safe_filename(filename):
        """Check if filename is safe"""
        if not filename:
            return False
        
        dangerous_patterns = [
            r'\.\.',  # Path traversal
            r'/',     # Directory separator
            r'\\',    # Windows directory separator
            r'|',     # Pipe
            r'&',     # Command separator
            r';',     # Command terminator
            r'$',     # Environment variable
            r'`',     # Command substitution
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, filename):
                return False
        
        return True