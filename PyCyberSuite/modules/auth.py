#
"""
This module provides the AuthSystem class for user authentication.
It loads user credentials from a JSON file and verifies login attempts.
Used for secure login in the CyberSuite application.
"""
import json
import hashlib
import os

class AuthSystem:
    def __init__(self, user_file='data/user.json'):
        self.user_file = user_file
        if not os.path.exists(user_file):
            raise FileNotFoundError(f"User file {user_file} not found")

    def verify_login(self, username: str, password: str) -> bool:
        """Check credentials against stored hash"""
        with open(self.user_file) as f:
            data = json.load(f)
        
        if username != data["username"]:
            return False
            
        hashed_input = hashlib.sha256(
            (password + data["salt"]).encode()
        ).hexdigest()
        
        return hashed_input == data["hash"]