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
        # Store the path to the user credentials file
        self.user_file = user_file
        # Check if the user file exists
        if not os.path.exists(user_file):
            raise FileNotFoundError(f"User file {user_file} not found")

    def verify_login(self, username: str, password: str) -> bool:
        """
        Verifies the login credentials by comparing the username and hashed password.
        Returns True if credentials match, False otherwise.
        """
        # Load user data from JSON file
        with open(self.user_file) as f:
            data = json.load(f)
        # Check if username matches
        if username != data["username"]:
            return False
        # Hash the input password with the stored salt
        hashed_input = hashlib.sha256(
            (password + data["salt"]).encode()
        ).hexdigest()
        # Compare the hash with the stored hash
        return hashed_input == data["hash"]