"""
Test file for the password checker module.
Explains and validates password strength evaluation and security checks.
Use this to demonstrate how password security is tested in PyCyberSuite.
"""
import unittest
import os
import sys
import pdb  # Import the Python debugger

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.password_checker import PasswordChecker

class TestPasswordChecker(unittest.TestCase):
    def test_complexity(self):
        """Test password complexity evaluation"""
        # pdb.set_trace()  # Start the debugger here
        checker = PasswordChecker("Short1!")
        self.assertIn("Weak", checker.check_complexity())
        checker = PasswordChecker("StrongPass123!")
        self.assertIn("Strong", checker.check_complexity())

    def test_breach(self):
        """Test password breach check using online API"""
        # pdb.set_trace()  # Start the debugger here
        checker = PasswordChecker("password")
        result = checker.check_breach()
        self.assertTrue("Found" in result or "Not found" in result)

if __name__ == "__main__":
    # Run all password checker tests
    unittest.main()

    # pdb commands like n for next lne c for continue q for quit