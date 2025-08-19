#
"""
This module provides the NetworkScanner class for scanning networks and hosts.
It uses nmap to detect live hosts and open ports.
Used for network reconnaissance in CyberSuite.
"""
import nmap

class NetworkScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def quick_scan(self, target_ip: str) -> dict:
        """Returns {host: [open_ports]} in simple format"""
        results = {}
        
        # Ping scan first
        self.scanner.scan(hosts=target_ip, arguments="-sn")
        
        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                results[host] = self._check_ports(host)
        
        return results

    def _check_ports(self, host: str) -> list:
        """Helper: Check common ports on a single host"""
        self.scanner.scan(hosts=host, arguments="-F")  # Fast scan
        open_ports = []
        
        for proto in self.scanner[host].all_protocols():
            for port, info in self.scanner[host][proto].items():
                if info['state'] == "open":
                    open_ports.append(f"{port}/{proto}")
        
        return open_ports