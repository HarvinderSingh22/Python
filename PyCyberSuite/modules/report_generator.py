"""
This module provides the ReportGenerator class for saving scan results, password checks, and encryption logs.
It can export all collected data to a JSON file for reporting and analysis.
Used for generating security reports in CyberSuite.
"""
import json                # For saving reports as JSON
from datetime import datetime  # For timestamps

class ReportGenerator:
    def __init__(self, filename="reports"):
        # Store the filename for the report
        self.filename = filename
        # Initialize the data dictionary with a timestamp
        self.data = {"generated": str(datetime.now()), "results": {}}

    def add_network_scan(self, results):
        # Add network scan results to the report
        self.data["network_scan"] = {
            "time": str(datetime.now()),
            "data": results
        }

    def add_password_test(self, password, complexity, breach):
        # Add password test results to the report
        self.data["password_test"] = {
            "password": password,
            "complexity": complexity,
            "breach": breach
        }

    def add_encryption_log(self, message, encrypted, decrypted):
        # Add encryption log to the report
        self.data["results"]["encryption_log"] = {
            "time": str(datetime.now()),
            "message": message,
            "encrypted": encrypted,
            "decrypted": decrypted
        }

    def save_as_json(self):
        # Save the report data as a JSON file
        with open(self.filename + ".json", "w") as f:
            json.dump(self.data, f, indent=4)
        print(f"[+] Report saved as {self.filename}.json")