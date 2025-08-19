#
"""
This module provides classes for symmetric and asymmetric encryption.
SymmetricEncryption uses a secret key for encrypting and decrypting messages.
AsymmetricEncryption uses public/private key pairs for secure communication.
Used for protecting sensitive data in CyberSuite.
"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class SymmetricEncryption:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def encrypt(self, message: str) -> bytes:
        return self.cipher.encrypt(message.encode())
    
    def decrypt(self, token: bytes) -> str:
        return self.cipher.decrypt(token).decode()
    
class AsymmetricEncryption:
    def __init__(self):  # Fixed typo: __int__ to __init__
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def encrypt(self, message: str) -> bytes:
        if isinstance(message, str):
            message = message.encode()
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, ciphertext: bytes) -> str:
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()