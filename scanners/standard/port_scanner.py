# scanners/standard/port_scanner.py
import socket
import time
from ..base_scanner import SecurityScanner

class PortScanner(SecurityScanner):
    """Standard port security scanner"""
    
    def run_scan(self):
        """Run port scan"""
        try:
            print(f"[*] Starting port scan for: {self.target_url}")
            self.update_progress(10, "🚀 Starting port scan...")
            
            # Parse the target URL to get hostname
            from urllib.parse import urlparse
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.hostname
            
            if not hostname:
                return self._build_results('error', error_message="Invalid URL")
            
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443, 3306, 5432, 27017]
            open_ports = []
            
            for i, port in enumerate(common_ports):
                if self.check_stop_flag():
                    return self._build_results('stopped')
                
                # Check if paused and wait
                self.check_pause_flag()
                
                progress = 10 + (i * 90 // len(common_ports))
                self.update_progress(progress, f"Scanning port {port}...", len(open_ports))
                
                if self.scan_port(hostname, port):
                    open_ports.append(port)
                    service = self.get_service_name(port)
                    
                    risk_level = 'High'
                    if port in [80, 443]:
                        risk_level = 'Low'
                    elif port in [21, 22, 23]:
                        risk_level = 'Medium'
                    
                    self.vulnerabilities.append({
                        'category': 'Open Port',
                        'risk_level': risk_level,
                        'title': f'Open Port Found: {port} ({service})',
                        'description': f'Port {port} ({service}) is accessible',
                        'location': f'{hostname}:{port}',
                        'recommendation': f'Close port {port} if not required for production use'
                    })
                
                time.sleep(0.1)  # Be nice
            
            self.update_progress(100, "✅ Port scan completed!", len(open_ports))
            
            return self._build_results('completed')
            
        except Exception as e:
            print(f"[-] Port scan error: {e}")
            return self._build_results('error', error_message=str(e))
    
    def scan_port(self, host, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt', 
            8443: 'HTTPS-Alt', 3306: 'MySQL', 5432: 'PostgreSQL',
            27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')