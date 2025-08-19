# PyCyberSuite

PyCyberSuite is an all-in-one Python cybersecurity toolkit with a modern Tkinter GUI. It integrates multiple modules for authentication, network scanning, password analysis, brute force simulation, dictionary attacks, encryption, subdomain enumeration, automation, and reporting.

## Features

- **Authentication**: Secure login system using a JSON user database.
- **Network Scanner**: Scan networks and hosts for open ports using nmap.
- **Subdomain Scanner**: Enumerate subdomains for a given domain using a wordlist.
- **Password Checker**: Analyze password complexity and check for breaches.
- **Encryption Tools**: Symmetric and asymmetric encryption for secure messaging.
- **Brute Force Simulator**: Demonstrate brute force password guessing.
- **Dictionary Attack**: Crack password hashes using a wordlist.
- **Automation**: Schedule network scans and password checks.
- **Report Generation**: Save results and logs to JSON reports.

## Project Structure

```
main.py                      # Main GUI application
requirements.txt             # Python dependencies
modules/                     # All core modules
    auth.py                  # Authentication logic
    automation.py            # Automation and scheduling
    brute_force_sim.py       # Brute force simulation
    crypto_tools.py          # Encryption tools
    dictionary_attack.py     # Dictionary attack logic
    network_scanner.py       # Network scanning
    password_checker.py      # Password analysis
    report_generator.py      # Report generation
    subdomain_file.py        # Subdomain enumeration
    __init__.py              # Module init
    __pycache__/             # Python cache files
reports/                     # Saved reports
data/                        # Data files
    demo_wordlist.txt        # Password wordlist
    user.json                # User database
    wordlists/
        sub_wordlist.txt     # Subdomain wordlist
        ...                  # Other wordlists

```

## Installation

1. Clone the repository:
   ```powershell
   git clone https://github.com/HarvinderSingh22/Python.git
   cd Python/PyCyberSuite
   ```
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

## Usage

Run the main application:
```powershell
python main.py
```

- Log in with your credentials (see `data/user.json`).
- Use the GUI to access all cybersecurity tools.
- Reports are saved in the `reports/` directory.

## Requirements

- Python 3.8+
- See `requirements.txt` for all required libraries (tkinter, cryptography, requests, python-nmap, schedule, etc.)

## Contributing

Pull requests and suggestions are welcome! Please open issues for bugs or feature requests.

## License

MIT License

---

**Note:** This toolkit is for educational and ethical use only. Do not use it for unauthorized penetration testing or attacks.
