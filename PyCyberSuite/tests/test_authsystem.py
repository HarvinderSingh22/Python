"""
Test file for the authentication system module.
Explains and validates login verification and user data management.
Use this to demonstrate how authentication is tested in PyCyberSuite.
"""
import unittest
import os
import json
import tempfile
import hashlib
import sys
import pdb  # Import the Python debugger

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.auth import AuthSystem

class TestAuthSystem(unittest.TestCase):
    def setUp(self):
        # Create a temporary user file for testing
        self.temp_dir = tempfile.TemporaryDirectory()
        self.user_file = os.path.join(self.temp_dir.name, 'user.json')
        salt = os.urandom(16).hex()
        password = "TestPass123!"
        hashed = hashlib.sha256((password + salt).encode()).hexdigest()
        user_data = {"username": "testuser", "salt": salt, "hash": hashed}
        with open(self.user_file, 'w') as f:
            json.dump(user_data, f)
        self.auth = AuthSystem(self.user_file)
        self.password = password
        self.salt = salt

    def tearDown(self):
        # Clean up temporary files after each test
        self.temp_dir.cleanup()

    def test_valid_login(self):
        """Test login with correct username and password"""
        # pdb.set_trace()  # Start the debugger here
        self.assertTrue(self.auth.verify_login("testuser", self.password))
    
    def test_invalid_username(self):
        """Test login with incorrect username"""
        # pdb.set_trace()  # Start the debugger here
        self.assertFalse(self.auth.verify_login("wronguser", self.password))

    def test_invalid_password(self):
        """Test login with incorrect password"""
        # pdb.set_trace()  # Start the debugger here
        self.assertFalse(self.auth.verify_login("testuser", "WrongPass!"))

if __name__ == "__main__":
    # Run all authentication tests
    unittest.main()
     # pdb commands like n for next lne c for continue q for quit