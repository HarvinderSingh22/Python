import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.password_checker import PasswordChecker

class TestPasswordChecker(unittest.TestCase):
    def test_complexity(self):
        checker = PasswordChecker("Short1!")
        self.assertIn("Weak", checker.check_complexity())
        checker = PasswordChecker("StrongPass123!")
        self.assertIn("Strong", checker.check_complexity())

    def test_breach(self):
        checker = PasswordChecker("password")
        result = checker.check_breach()
        self.assertTrue("Found" in result or "Not found" in result)

if __name__ == "__main__":
    unittest.main()