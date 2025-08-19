#
"""
This module provides the SubdomainEnumerator class for finding subdomains of a given domain using a wordlist.
It helps identify possible entry points for attacks.
Used for subdomain enumeration in CyberSuite.
"""
import socket

class SubdomainEnumerator:
    def __init__(self, domain, domain_wordlist):
        self.domain = domain
        self.domain_wordlist = domain_wordlist
        
    def enumerate(self):
        found_subdomains = []
        for sub in self.domain_wordlist:
            subdomain = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                print(ip)
                found_subdomains.append(subdomain)
            except socket.gaierror:
                pass
        return found_subdomains
