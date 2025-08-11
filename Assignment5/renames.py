import os

folder = r'C:\Users\offic\Documents\GitHub\Python\Assignment5\folder'

for f in os.listdir(folder):
    if f.endswith(".txt"):
        os.rename(os.path.join(folder, f), os.path.join(folder, f"processed_{f}"))
