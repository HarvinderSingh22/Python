import hashlib

password = "123456"
hashed = hashlib.sha256(password.encode()).hexdigest()

print("SHA-256 Hash:", hashed)
