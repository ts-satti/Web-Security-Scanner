import re

class InputValidators:
    """Input validation utilities"""
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        if not email:
            return False, "Email cannot be empty"
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return False, "Invalid email format"
        
        return True, "Email is valid"
    
    @staticmethod
    def validate_password(password):
        """Validate password strength"""
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        
        return True, "Password is valid"
    
    @staticmethod
    def validate_scan_type(scan_type):
        """Validate scan type"""
        valid_types = {
            'owasp_top_10', 'xss', 'sqli', 'csrf', 
            'headers', 'info_disclosure', 'port_scan', 'deep_scan'
        }
        
        if scan_type not in valid_types:
            return False, f"Invalid scan type: {scan_type}"
        
        return True, "Scan type is valid"