#
"""
This module provides the PasswordChecker class for evaluating password strength and checking for breaches.
It checks complexity and queries breach databases to see if a password has been compromised.
Used for password security analysis in CyberSuite.
"""
import re
import hashlib
import requests

class PasswordChecker:
    def __init__(self, password):
        self.password = password

    def check_complexity(self):
        if len(self.password) < 8:
            return "Weak: Password too short"
        if not re.search(r"[A-Z]", self.password):
            return "Weak: Missing uppercase letter"
        if not re.search(r"[a-z]", self.password):
            return "Weak: Missing lowercase letter"
        if not re.search(r"\d", self.password):
            return "Weak: Missing number"
        if not re.search(r"[!@#$%^&*]", self.password):
            return "Weak: Missing special character"
        return "Strong password"
    
    def check_breach(self):
        sha1 = hashlib.sha1(self.password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        
        try:
            response = requests.get(url)
            if response.status_code != 200:
                return "Error: Could not check breach"
                
            for line in response.text.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    hash_suffix, count = parts[0], parts[1]
                    if hash_suffix == suffix:
                        return f"Found in breaches {count} times!"
            return "Not found in breaches"
        except Exception as e:
            return f"Error: {str(e)}"