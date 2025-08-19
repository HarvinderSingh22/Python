"""
This module provides the DictionaryAttack class for cracking password hashes using a wordlist.
It compares the SHA-256 hash of each word in the list to the target hash.
Used for demonstrating dictionary attacks in CyberSuite.
"""
import hashlib  # For hashing passwords

class DictionaryAttack:
    @staticmethod
    def dictionary_attack_sha256(target_hash, wordlist_path):
        """
        Attempts to crack the target hash using a wordlist.
        Returns the password if found, None otherwise.
        """
        try:
            # Open the wordlist file and check each password
            with open(wordlist_path, 'r') as file:
                for line in file:
                    password = line.strip()  # Remove whitespace/newline
                    # Hash the password using SHA-256
                    hashed = hashlib.sha256(password.encode()).hexdigest()
                    # Compare the hash to the target hash
                    if hashed == target_hash:
                        return password  # Return the password if found
            return None  # Return None if not found
        except Exception as e:
            # Print error message if something goes wrong
            print(f"Error in dictionary attack: {e}")
            return None