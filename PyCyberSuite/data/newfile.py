import hashlib
import json
import secrets

# Prompt user for password
password = input("Enter new password for user 'Harry': ")

# Generate a random salt
salt = secrets.token_hex(16)

# Create hash using SHA-256
hash_value = hashlib.sha256((password + salt).encode()).hexdigest()

# Prepare user data
user_data = {
	"username": "Harry",
	"hash": hash_value,
	"salt": salt
}

# Save to user.json
with open("data/user.json", "w") as f:
	json.dump(user_data, f, indent=4)

print(f"Password: {password}")
print(f"Salt: {salt}")
print(f"Hash: {hash_value}")
print("user.json updated!")
