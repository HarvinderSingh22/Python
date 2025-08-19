"""
Test file for the symmetric encryption module.
Explains and validates encryption and decryption functionality.
Use this to demonstrate how encryption is tested in PyCyberSuite.
"""
import unittest
import os
import sys
import pdb  # Import the Python debugger

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.crypto_tools import SymmetricEncryption

class TestSymmetricEncryption(unittest.TestCase):
    def test_encrypt_decrypt(self):
        """Test that encryption and decryption work correctly"""
        # pdb.set_trace()  # Start the debugger here
        crypto = SymmetricEncryption()  # Create encryption object
        message = "SecretMessage"      # Message to encrypt
        encrypted = crypto.encrypt(message)  # Encrypt the message
        decrypted = crypto.decrypt(encrypted)  # Decrypt the message
        self.assertEqual(decrypted, message)  # Check if decrypted matches original

if __name__ == "__main__":
    # Run all symmetric encryption tests
    unittest.main()
    # pdb commands like n for next line c for continue q for quit