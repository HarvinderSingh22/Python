"""
This module provides the NetworkScanner class for scanning networks and hosts.
It uses nmap to detect live hosts and open ports.
Used for network reconnaissance in CyberSuite.
"""
import nmap  # Import the nmap library for network scanning
import socket  # For getting the system's IP address

class NetworkScanner:
    def __init__(self):
        # Initialize the nmap PortScanner object
        self.scanner = nmap.PortScanner()

    def get_local_ip(self):
        """
        Get the local IP address of the system.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't have to be reachable, just used to get the local IP
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def quick_scan(self) -> dict:
        """
        Perform a quick scan on the system's local IP address.
        Returns a dictionary mapping each live host to its list of open ports.
        """
        target_ip = self.get_local_ip()  # Get system IP automatically
        results = {}  # Dictionary to store scan results
        
        # First, perform a ping scan to find live hosts
        self.scanner.scan(hosts=target_ip, arguments="-sn")
        
        # Iterate through all detected hosts
        for host in self.scanner.all_hosts():
            # Check if the host is up (responding to ping)
            if self.scanner[host].state() == "up":
                # For each live host, check its open ports
                results[host] = self._check_ports(host)
        
        return results

    def _check_ports(self, host: str) -> list:
        """
        Helper function to check common ports on a single host.
        Returns a list of open ports in the format 'port/protocol'.
        """
        # Perform a fast scan on the host to check common ports
        self.scanner.scan(hosts=host, arguments="-F")  # Fast scan
        open_ports = []  # List to store open ports
        
        # Iterate through all protocols detected on the host
        for proto in self.scanner[host].all_protocols():
            # For each protocol, check all ports
            for port, info in self.scanner[host][proto].items():
                # If the port is open, add it to the list
                if info['state'] == "open":
                    open_ports.append(f"{port}/{proto}")
        
        return open_ports