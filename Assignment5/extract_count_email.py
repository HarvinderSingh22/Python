import re

def extract_emails(input_file):
    
 with open(input_file, "r") as file:
     text = file.read()
 
 pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
 
 
 emails = re.findall(pattern, text)
 
 
 unique_emails = sorted(set(emails))
 
 
 print(f"Total unique emails: {len(unique_emails)}")
 print("Emails in alphabetical order:")
 for email in unique_emails:
     print(email)
extract_emails("emails.txt")