import unittest
import os
import json
import tempfile
import hashlib
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.auth import AuthSystem

class TestAuthSystem(unittest.TestCase):
    def setUp(self):
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
        self.temp_dir.cleanup()

    def test_valid_login(self):
        self.assertTrue(self.auth.verify_login("testuser", self.password))

    def test_invalid_username(self):
        self.assertFalse(self.auth.verify_login("wronguser", self.password))

    def test_invalid_password(self):
        self.assertFalse(self.auth.verify_login("testuser", "WrongPass!"))

if __name__ == "__main__":
    unittest.main()
