#
"""
This module provides the DictionaryAttack class for cracking password hashes using a wordlist.
It compares the SHA-256 hash of each word in the list to the target hash.
Used for demonstrating dictionary attacks in CyberSuite.
"""
import hashlib

class DictionaryAttack:
    @staticmethod
    def dictionary_attack_sha256(target_hash, wordlist_path):
        try:
            with open(wordlist_path, 'r') as file:
                for line in file:
                    password = line.strip()
                    hashed = hashlib.sha256(password.encode()).hexdigest()
                    if hashed == target_hash:
                        return password
            return None
        except Exception as e:
            print(f"Error in dictionary attack: {e}")
            return None
