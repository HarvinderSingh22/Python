import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.crypto_tools import SymmetricEncryption

class TestSymmetricEncryption(unittest.TestCase):
    def test_encrypt_decrypt(self):
        crypto = SymmetricEncryption()
        message = "SecretMessage"
        encrypted = crypto.encrypt(message)
        decrypted = crypto.decrypt(encrypted)
        self.assertEqual(decrypted, message)

if __name__ == "__main__":
    unittest.main()
