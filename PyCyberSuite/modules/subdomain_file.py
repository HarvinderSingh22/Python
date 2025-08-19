"""
This module provides the SubdomainEnumerator class for finding subdomains of a given domain using a wordlist.
It helps identify possible entry points for attacks.
Used for subdomain enumeration in CyberSuite.
"""
import socket  # For DNS resolution

class SubdomainEnumerator:
    def __init__(self, domain, domain_wordlist):
        # Store the domain and wordlist for enumeration
        self.domain = domain
        self.domain_wordlist = domain_wordlist
        
    def enumerate(self):
        """
        Enumerates subdomains by attempting to resolve each one.
        Returns a list of found subdomains.
        """
        found_subdomains = []  # List to store discovered subdomains
        for sub in self.domain_wordlist:
            subdomain = f"{sub}.{self.domain}"  # Build the full subdomain
            try:
                # Try to resolve the subdomain to an IP address
                ip = socket.gethostbyname(subdomain)
                print(ip)  # Print the IP address (for demonstration)
                found_subdomains.append(subdomain)  # Add to found list
            except socket.gaierror:
                # If resolution fails, skip this subdomain
                pass
        return found_subdomains  # Return all found subdomains