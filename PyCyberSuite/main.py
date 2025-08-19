import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
import schedule
import time
import json
from datetime import datetime
import os
from modules.auth import AuthSystem
from modules.network_scanner import NetworkScanner
from modules.automation import AutomationModule
from modules.report_generator import ReportGenerator
from modules.crypto_tools import SymmetricEncryption, AsymmetricEncryption
from modules.password_checker import PasswordChecker
from modules.brute_force_sim import BruteForceSimulator
from modules.dictionary_attack import DictionaryAttack
from modules.subdomain_file import SubdomainEnumerator


# CyberSuite is the main GUI application for the cybersecurity toolkit.
# It integrates authentication, scanning, password checking, encryption, brute force, dictionary attack, automation, and reporting tools.
#
# UI is styled like a hacker console: neon green on black, monospace font, grid layout for tools.
#
# Keyboard handling: currently, all actions are triggered by button clicks. You can add keyboard shortcuts using self.root.bind().


class CyberSuite:
    def __init__(self):
        # Initialize the main window and hacking-style theme
        """
        Initialize the CyberSuite GUI, configure styles, and set up all modules.
        """
        self.root = tk.Tk()  # Create main window
        self.root.title("PyCyberSuite - [Hacker Console]")  # Set window title
        self.root.geometry("950x750")  # Set window size
        self.root.configure(bg="#101010")  # Set background color

        # Set ttk style for hacking theme
    # Set ttk style for hacking theme (neon green, monospace)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#101010', foreground='#39ff14', font=('Consolas', 11))
        style.configure('TLabel', background='#101010', foreground='#39ff14', font=('Consolas', 14, 'bold'))
        style.configure('TButton', background='#101010', foreground='#39ff14', font=('Consolas', 12, 'bold'), borderwidth=2, focusthickness=3)
        style.map('TButton', background=[('active', '#222'), ('pressed', '#222')], foreground=[('active', '#00ffea')])
        style.configure('TEntry', fieldbackground='#222', foreground='#39ff14', font=('Consolas', 12))
        style.configure('TFrame', background='#101010')
        style.configure('TLabelframe', background='#101010', foreground='#39ff14', font=('Consolas', 13, 'bold'))
        style.configure('TLabelframe.Label', background='#101010', foreground='#39ff14', font=('Consolas', 13, 'bold'))

    # Custom title bar (simple)
    # Custom title bar for hacker look
        title_bar = tk.Frame(self.root, bg='#101010', relief='raised', bd=0)
        title_bar.pack(fill=tk.X)
        logo = tk.Label(title_bar, text='[💻]', fg='#39ff14', bg='#101010', font=('Consolas', 16, 'bold'))
        logo.pack(side=tk.LEFT, padx=10)
        title = tk.Label(title_bar, text='PyCyberSuite - Hacker Console', fg='#39ff14', bg='#101010', font=('Consolas', 16, 'bold'))
        title.pack(side=tk.LEFT, padx=5)
        close_btn = tk.Button(title_bar, text='✖', fg='#39ff14', bg='#101010', font=('Consolas', 14, 'bold'), bd=0, command=self.root.quit, activebackground='#222', activeforeground='#ff0055')
        close_btn.pack(side=tk.RIGHT, padx=10)
    
            # Initialize tools
            # Initialize all tool modules
        try:
                self.auth = AuthSystem()  # Authentication system
                self.net_scanner = NetworkScanner()  # Network scanner
                self.wordlist = self.load_wordlist("data/wordlists/sub_wordlist.txt")  # Wordlist for subdomain scanner
                self.report_gen = ReportGenerator()  # Report generator
                self.symmetric_crypto = SymmetricEncryption()  # Symmetric encryption
                self.auto_running = False  # Automation flag
        except Exception as e:
                messagebox.showerror(
                    "Initialization Error", f"Failed to initialize tools: {str(e)}"
                )
                self.root.destroy()
                return
    
        # Start with login screen
        self.show_login()

    def load_wordlist(self, filename):
        # Loads a wordlist from file for subdomain enumeration
        """
        Load a wordlist from a file for subdomain enumeration.
        """
        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename) as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ["www", "mail", "api", "vpn"]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load wordlist: {str(e)}")
            return []

    def clear_window(self):
        # Removes all widgets from the main window (used to switch screens)
        """
        Remove all widgets from the main window.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self):
        # Displays the login screen for user authentication
        """
        Display the login screen for user authentication.
        """
        self.clear_window()
        frame = ttk.Frame(self.root, padding=30, style='TFrame')
        frame.pack(expand=True)
        ttk.Label(frame, text="CyberSuite Login", font=("Consolas", 25, "bold"), style='TLabel').grid(row=0, columnspan=2, pady=20)
        ttk.Label(frame, text="Username:", font=("Consolas", 16, "bold"),  style='TLabel').grid(row=1, column=0, sticky="e", pady=5)
        self.username_entry = ttk.Entry(frame, style='TEntry')  # Username input
        self.username_entry.grid(row=1, column=1, pady=5, padx=5)
        ttk.Label(frame, text="Password:",font=("Consolas", 16, "bold"), style='TLabel').grid(row=2, column=0, sticky="e", pady=5)
        self.password_entry = ttk.Entry(frame, show="*", style='TEntry')  # Password input
        self.password_entry.grid(row=2, column=1, pady=5, padx=5)
        btn_frame = ttk.Frame(frame, style='TFrame')  # Button area
        btn_frame.grid(row=3, columnspan=2, pady=20)
        ttk.Button(btn_frame, text="Login", command=self.attempt_login, style='TButton').pack(side=tk.LEFT, padx=5)  # Login button
        ttk.Button(btn_frame, text="Exit", command=self.root.quit, style='TButton').pack(side=tk.LEFT, padx=5)  # Exit button
        self.status_label = ttk.Label(frame, text="", foreground="#39ff14", style='TLabel')  # Status message
        self.status_label.grid(row=4, columnspan=2)
        self.username_entry.focus()

    def attempt_login(self):
        # Handles login logic when user clicks Login
        """
        Attempt to log in with the provided username and password.
        """
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            self.status_label.config(text="Both fields are required!")
            return

        try:
            if self.auth.verify_login(username, password):
                self.show_main_menu()  # Show main menu if login successful
            else:
                self.status_label.config(text="Invalid credentials")  # Show error if login fails
        except Exception as e:
            self.status_label.config(text="Login failed")

    def show_main_menu(self):
        # Displays the main menu with all available cybersecurity tools in a grid layout
        """
        Display the main menu with all available cybersecurity tools in a refined hacking-style layout.
        """
        self.clear_window()
        frame = ttk.Frame(self.root, padding=40, style='TFrame')
        frame.pack(expand=True)
    # Section header (hacker style)
        ttk.Label(frame, text="[ PyCyberSuite - Hacker Console ]", font=("Consolas", 22, "bold"), style='TLabel').pack(pady=(10, 30))
        # Divider
        divider = ttk.Separator(frame, orient='horizontal')  # Divider line
        divider.pack(fill=tk.X, padx=20, pady=(0, 30))
        # Menu area - grid layout for hacking console look
        menu_frame = ttk.Frame(frame, style='TFrame')  # Menu area for tool buttons
        menu_frame.pack(expand=True)
        tools = [
            ("[1] Network Scanner", self.show_network_scanner),
            ("[2] Subdomain Scanner", self.show_subdomain_scanner),
            ("[3] Password Checker", self.show_password_checker),
            ("[4] Encryption Tools", self.show_crypto_tools),
            ("[5] Brute Force Simulator", self.show_brute_force),
            ("[6] Dictionary Attack", self.show_dictionary_attack),
            ("[7] Automation", self.show_automation),
            ("[8] Generate Report", self.generate_report),
            ("[9] Logout", self.show_login),
        ]
        # Arrange buttons in a grid (3 columns) for hacking console look
        cols = 3
        for idx, (text, cmd) in enumerate(tools):
            row, col = divmod(idx, cols)
            btn = ttk.Button(menu_frame, text=text, command=cmd, style='TButton')
            btn.grid(row=row, column=col, padx=30, pady=18, sticky="ew")  # Tool button
        # Make columns expand equally
        for c in range(cols):
            menu_frame.grid_columnconfigure(c, weight=1)

        # Example keyboard shortcut: press Escape to logout
            self.root.bind('<Escape>', lambda event: self.show_login())
            ("[2] Subdomain Scanner", self.show_subdomain_scanner),
            ("[3] Password Checker", self.show_password_checker),
            ("[4] Encryption Tools", self.show_crypto_tools),
            ("[5] Brute Force Simulator", self.show_brute_force),
            ("[6] Dictionary Attack", self.show_dictionary_attack),
            ("[7] Automation", self.show_automation),
            ("[8] Generate Report", self.generate_report),
            ("[9] Logout", self.show_login),
        

    # Network Scanner Methods
    def show_network_scanner(self):
        """
        Show the network scanner tool interface.
        """
        self.clear_window()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Network Scanner", font=("Arial", 14)).pack(pady=10)

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)

        ttk.Label(input_frame, text="Target:").pack(side=tk.LEFT)
        self.net_target_entry = ttk.Entry(input_frame)
        self.net_target_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.net_target_entry.insert(0, "192.168.56.1/24")

        ttk.Button(frame, text="Start Scan", command=self.start_network_scan).pack(
            pady=10
        )

        self.net_results = tk.Text(frame, height=20)
        scrollbar = ttk.Scrollbar(frame, command=self.net_results.yview)
        self.net_results.config(yscrollcommand=scrollbar.set)

        self.net_results.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu).pack(
            pady=10
        )

    def start_network_scan(self):
        """
        Start a network scan for the specified target.
        """
        target = self.net_target_entry.get().strip()
        if not target:
            messagebox.showwarning("Error", "Please enter a target")
            return

        self.net_results.delete(1.0, tk.END)
        self.net_results.insert(tk.END, "Scanning...\n")

        Thread(target=self.run_network_scan, args=(target,), daemon=True).start()

    def run_network_scan(self, target):
        """
        Run the network scan in a separate thread and display results.
        """
        try:
            results = self.net_scanner.quick_scan(target)
            self.root.after(0, self.display_network_results, results)
            self.report_gen.add_network_scan(results)
        except Exception as e:
            self.root.after(0, lambda e=e: messagebox.showerror("Scan Error", str(e)))

    def display_network_results(self, results):
        """
        Display the results of the network scan in the GUI.
        """
        self.net_results.delete(1.0, tk.END)

        if not results:
            self.net_results.insert(tk.END, "No hosts found")
            return

        for host, ports in results.items():
            self.net_results.insert(tk.END, f"\nHost: {host}\n")
            for port in ports:
                self.net_results.insert(tk.END, f"• {port} open ports\n")

    # Subdomain Scanner Methods
    def show_subdomain_scanner(self):
        """
        Show the subdomain scanner tool interface.
        """
        self.clear_window()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Subdomain Scanner", font=("Arial", 14)).pack(pady=10)

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)

        ttk.Label(input_frame, text="Domain:").pack(side=tk.LEFT)
        self.subdomain_entry = ttk.Entry(input_frame)
        self.subdomain_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.subdomain_entry.insert(0, "example.com")

        wordlist_frame = ttk.Frame(frame)
        wordlist_frame.pack(fill=tk.X, pady=10)

        ttk.Label(wordlist_frame, text="Wordlist:").pack(side=tk.LEFT)
        self.wordlist_entry = ttk.Entry(wordlist_frame)
        self.wordlist_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.wordlist_entry.insert(0, "data/wordlists/sub_wordlist.txt")

        ttk.Button(
            wordlist_frame, text="Browse", command=self.browse_wordlist, width=10
        ).pack(side=tk.LEFT)

        ttk.Button(frame, text="Start Scan", command=self.start_subdomain_scan).pack(
            pady=10
        )

        self.subdomain_results = tk.Text(frame, height=20)
        scrollbar = ttk.Scrollbar(frame, command=self.subdomain_results.yview)
        self.subdomain_results.config(yscrollcommand=scrollbar.set)

        self.subdomain_results.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu).pack(
            pady=10
        )

    def browse_wordlist(self):
        """
        Open a file dialog to select a wordlist for subdomain scanning.
        """
        path = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
            initialfile="sub_wordlist.txt",
        )
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

    def start_subdomain_scan(self):
        """
        Start subdomain enumeration for the specified domain.
        """
        domain = self.subdomain_entry.get().strip()
        wordlist_path = self.wordlist_entry.get().strip()

        if not domain:
            messagebox.showwarning("Error", "Please enter a domain")
            return

        try:
            with open(wordlist_path) as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load wordlist: {str(e)}")
            return

        self.subdomain_results.delete(1.0, tk.END)
        self.subdomain_results.insert(tk.END, f"Scanning {domain}...\n")

        Thread(
            target=self.run_subdomain_scan, args=(domain, wordlist), daemon=True
        ).start()

    def run_subdomain_scan(self, domain, wordlist):
        """
        Run subdomain enumeration in a separate thread and display results.
        """
        try:
            scanner = SubdomainEnumerator(domain, wordlist)
            found = scanner.enumerate()
            self.root.after(0, self.display_subdomain_results, found)
        except Exception as e:
            self.root.after(0, lambda e=e: messagebox.showerror("Scan Error", str(e)))

    def display_subdomain_results(self, found):
        """
        Display the results of subdomain enumeration in the GUI.
        """
        self.subdomain_results.delete(1.0, tk.END)

        if not found:
            self.subdomain_results.insert(tk.END, "No subdomains found")
            return

        self.subdomain_results.insert(tk.END, f"Found {len(found)} subdomains:\n\n")
        for sub in found:
            self.subdomain_results.insert(tk.END, f"• {sub}\n")

    # Password Checker Methods
    def show_password_checker(self):
        """
        Show the password checker tool interface.
        """
        self.clear_window()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Password Checker", font=("Arial", 14)).pack(pady=10)

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)

        ttk.Label(input_frame, text="Password:").pack(side=tk.LEFT)
        self.password_check_entry = ttk.Entry(input_frame, show="*")
        self.password_check_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            btn_frame, text="Check Complexity", command=self.check_complexity
        ).pack(side=tk.LEFT, expand=True, padx=5)

        ttk.Button(btn_frame, text="Check Breaches", command=self.check_breaches).pack(
            side=tk.LEFT, expand=True, padx=5
        )

        self.pw_results = tk.Text(frame, height=10)
        scrollbar = ttk.Scrollbar(frame, command=self.pw_results.yview)
        self.pw_results.config(yscrollcommand=scrollbar.set)

        self.pw_results.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu).pack(
            pady=10
        )

    def check_complexity(self):
        """
        Check the complexity of the entered password.
        """
        password = self.password_check_entry.get()
        if not password:
            messagebox.showwarning("Error", "Please enter a password")
            return

        checker = PasswordChecker(password)
        result = checker.check_complexity()
        self.pw_results.delete(1.0, tk.END)
        self.pw_results.insert(tk.END, "=== Complexity Check ===\n")
        self.pw_results.insert(tk.END, f"Result: {result}\n")

    def check_breaches(self):
        """
        Check if the entered password has been breached.
        """
        password = self.password_check_entry.get()
        if not password:
            messagebox.showwarning("Error", "Please enter a password")
            return

        self.pw_results.delete(1.0, tk.END)
        self.pw_results.insert(tk.END, "Checking breaches...\n")

        Thread(target=self.run_breach_check, args=(password,), daemon=True).start()

    def run_breach_check(self, password):
        """
        Run breach check in a separate thread and display results.
        """
        try:
            checker = PasswordChecker(password)
            result = checker.check_breach()
            self.root.after(0, self.display_breach_result, result)
            self.report_gen.add_password_test(
                password, checker.check_complexity(), result
            )
        except Exception as e:
            self.root.after(0, lambda e=e: messagebox.showerror("API Error", str(e)))

    def display_breach_result(self, result):
        """
        Display the result of the breach check in the GUI.
        """
        self.pw_results.insert(tk.END, "\n=== Breach Check ===\n")
        self.pw_results.insert(tk.END, f"Result: {result}\n")

    # Crypto Tools Section
    def show_crypto_tools(self):
        """
        Show the encryption tools interface for symmetric and asymmetric encryption.
        """
        self.clear_window()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Encryption Tools", font=("Arial", 14)).pack(pady=10)

        sym_frame = ttk.LabelFrame(frame, text="Symmetric Encryption", padding=10)
        sym_frame.pack(fill=tk.X, pady=5)

        ttk.Label(sym_frame, text="Message:").pack(anchor=tk.W)
        self.sym_message = ttk.Entry(sym_frame)
        self.sym_message.pack(fill=tk.X, pady=5)

        btn_frame = ttk.Frame(sym_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="Encrypt", command=self.symmetric_encrypt).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(btn_frame, text="Decrypt", command=self.symmetric_decrypt).pack(
            side=tk.LEFT, padx=5
        )

        self.sym_result = tk.Text(sym_frame, height=5)
        self.sym_result.pack(fill=tk.X)

        asym_frame = ttk.LabelFrame(frame, text="Asymmetric Encryption", padding=10)
        asym_frame.pack(fill=tk.X, pady=5)

        ttk.Label(asym_frame, text="Message:").pack(anchor=tk.W)
        self.asym_message = ttk.Entry(asym_frame)
        self.asym_message.pack(fill=tk.X, pady=5)

        btn_frame = ttk.Frame(asym_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="Encrypt", command=self.asymmetric_encrypt).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(btn_frame, text="Decrypt", command=self.asymmetric_decrypt).pack(
            side=tk.LEFT, padx=5
        )

        self.asym_result = tk.Text(asym_frame, height=5)
        self.asym_result.pack(fill=tk.X)

        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu).pack(
            pady=10
        )

    def symmetric_encrypt(self):
        """
        Encrypt the entered message using symmetric encryption.
        """
        message = self.sym_message.get()
        if not message:
            messagebox.showwarning("Error", "Please enter a message")
            return

        try:
            encrypted = self.symmetric_crypto.encrypt(message)
            self.sym_result.delete(1.0, tk.END)
            self.sym_result.insert(tk.END, f"Encrypted: {encrypted.decode()}")
            self.report_gen.add_encryption_log(message, encrypted.decode(), "")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def symmetric_decrypt(self):
        """
        Decrypt the entered token using symmetric encryption.
        """
        token = self.sym_result.get(1.0, tk.END).strip()
        if not token or not token.startswith("Encrypted: "):
            messagebox.showwarning("Error", "Nothing to decrypt")
            return

        try:
            token = token.replace("Encrypted: ", "")
            decrypted = self.symmetric_crypto.decrypt(token.encode())
            self.sym_result.insert(tk.END, f"\nDecrypted: {decrypted}")
            self.report_gen.add_encryption_log("", token, decrypted)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def asymmetric_encrypt(self):
        """
        Encrypt the entered message using asymmetric encryption.
        """
        message = self.asym_message.get()
        if not message:
            messagebox.showwarning("Error", "Please enter a message")
            return

        try:
            if not hasattr(self, "asymmetric_crypto"):
                self.asymmetric_crypto = AsymmetricEncryption()

            encrypted = self.asymmetric_crypto.encrypt(message)
            self.asym_result.delete(1.0, tk.END)
            self.asym_result.insert(tk.END, f"Encrypted: {encrypted.hex()}")
            self.report_gen.add_encryption_log(message, encrypted.hex(), "")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def asymmetric_decrypt(self):
        """
        Decrypt the entered token using asymmetric encryption.
        """
        token = self.asym_result.get(1.0, tk.END).strip()
        if not token or not token.startswith("Encrypted: "):
            messagebox.showwarning("Error", "Nothing to decrypt")
            return

        try:
            token = bytes.fromhex(token.replace("Encrypted: ", ""))
            decrypted = self.asymmetric_crypto.decrypt(token)
            self.asym_result.insert(tk.END, f"\nDecrypted: {decrypted}")
            self.report_gen.add_encryption_log("", token.hex(), decrypted)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # Brute Force Simulator Section
    def show_brute_force(self):
        """
        Show the brute force simulator tool interface.
        """
        self.clear_window()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Brute Force Simulator", font=("Arial", 14)).pack(pady=10)

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)

        ttk.Label(input_frame, text="Target Password:").pack(side=tk.LEFT)
        self.bf_password = ttk.Entry(input_frame)
        self.bf_password.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        ttk.Label(input_frame, text="Max Length:").pack(side=tk.LEFT, padx=5)
        self.bf_max_length = ttk.Spinbox(input_frame, from_=1, to=8, width=3)
        self.bf_max_length.pack(side=tk.LEFT)
        self.bf_max_length.set(3)

        ttk.Button(
            frame, text="Simulate Attack", command=self.run_brute_force_sim
        ).pack(pady=10)

        self.bf_results = tk.Text(frame, height=15)
        scrollbar = ttk.Scrollbar(frame, command=self.bf_results.yview)
        self.bf_results.config(yscrollcommand=scrollbar.set)

        self.bf_results.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu).pack(
            pady=10
        )

    def run_brute_force_sim(self):
        """
        Start brute force simulation for the entered password and max length.
        """
        password = self.bf_password.get()
        max_length = int(self.bf_max_length.get())

        if not password:
            messagebox.showwarning("Error", "Please enter a password")
            return

        self.bf_results.delete(1.0, tk.END)
        self.bf_results.insert(tk.END, "Starting brute force simulation...\n")

        Thread(
            target=self._run_brute_force, args=(password, max_length), daemon=True
        ).start()

    def _run_brute_force(self, password, max_length):
        """
        Run brute force simulation in a separate thread and display results.
        """
        try:
            simulator = BruteForceSimulator(password, max_length)
            result, attempts = simulator.simulate()
            if result:
                self.root.after(
                    0, lambda: self.bf_results.insert(tk.END, f"\nPassword found: {result}\nAttempts: {attempts}\n")
                )
            else:
                self.root.after(
                    0, lambda: self.bf_results.insert(tk.END, f"\nPassword not found after {attempts} attempts.\n")
                )
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

    # Dictionary Attack Section
    def show_dictionary_attack(self):
        """
        Show the dictionary attack tool interface.
        """
        self.clear_window()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Dictionary Attack", font=("Arial", 14)).pack(pady=10)

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)

        ttk.Label(input_frame, text="Target Hash:").pack(side=tk.LEFT)
        self.da_hash = ttk.Entry(input_frame)
        self.da_hash.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        wordlist_frame = ttk.Frame(frame)
        wordlist_frame.pack(fill=tk.X, pady=10)

        ttk.Label(wordlist_frame, text="Wordlist:").pack(side=tk.LEFT)
        self.da_wordlist = ttk.Entry(wordlist_frame)
        self.da_wordlist.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.da_wordlist.insert(0, "data/demo_wordlist.txt")

        ttk.Button(
            wordlist_frame, text="Browse", command=self.browse_da_wordlist, width=10
        ).pack(side=tk.LEFT)

        ttk.Button(frame, text="Run Attack", command=self.run_dictionary_attack).pack(
            pady=10
        )

        self.da_results = tk.Text(frame, height=10)
        scrollbar = ttk.Scrollbar(frame, command=self.da_results.yview)
        self.da_results.config(yscrollcommand=scrollbar.set)

        self.da_results.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu).pack(
            pady=10
        )

    def browse_da_wordlist(self):
        """
        Open a file dialog to select a wordlist for dictionary attack.
        """
        path = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
            initialfile="demo_wordlist",
        )
        if path:
            self.da_wordlist.delete(0, tk.END)
            self.da_wordlist.insert(0, path)

    def run_dictionary_attack(self):
        """
        Start dictionary attack for the entered hash and wordlist.
        """
        target_hash = self.da_hash.get().strip()
        wordlist_path = self.da_wordlist.get().strip()

        if not target_hash:
            messagebox.showwarning("Error", "Please enter a target hash")
            return

        self.da_results.delete(1.0, tk.END)
        self.da_results.insert(tk.END, f"Starting dictionary attack...\n")

        Thread(
            target=self._run_dictionary_attack,
            args=(target_hash, wordlist_path),
            daemon=True,
        ).start()

    def _run_dictionary_attack(self, target_hash, wordlist_path):
        """
        Run dictionary attack in a separate thread and display results.
        """
        try:
            result = DictionaryAttack.dictionary_attack_sha256(
                target_hash, wordlist_path
            )
            self.root.after(
                0, lambda: self.da_results.insert(tk.END, f"\nResult: {result}\n")
            )
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

    # Automation Section
    def show_automation(self):
        """
        Show the automation tool interface for scheduling scans and checks.
        """
        self.clear_window()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Automation", font=("Arial", 14)).pack(pady=10)

        net_frame = ttk.LabelFrame(frame, text="Network Scan", padding=10)
        net_frame.pack(fill=tk.X, pady=5)

        ttk.Label(net_frame, text="Time (HH:MM):").pack(side=tk.LEFT)
        self.net_scan_time = ttk.Entry(net_frame, width=8)
        self.net_scan_time.pack(side=tk.LEFT, padx=5)
        self.net_scan_time.insert(0, "01:08")

        ttk.Label(net_frame, text="Target:").pack(side=tk.LEFT, padx=5)
        self.net_scan_target = ttk.Entry(net_frame)
        self.net_scan_target.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.net_scan_target.insert(0, "192.168.56.1")

        pw_frame = ttk.LabelFrame(frame, text="Password Check", padding=10)
        pw_frame.pack(fill=tk.X, pady=5)

        ttk.Label(pw_frame, text="Time (HH:MM:SS):").pack(side=tk.LEFT)
        self.pw_check_time = ttk.Entry(pw_frame, width=8)
        self.pw_check_time.pack(side=tk.LEFT, padx=5)
        self.pw_check_time.insert(0, "01:08:20")

        ttk.Label(pw_frame, text="Password:").pack(side=tk.LEFT, padx=5)
        self.pw_check_password = ttk.Entry(pw_frame)
        self.pw_check_password.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.pw_check_password.insert(0, "Hello123!")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            btn_frame, text="Start Automation", command=self.start_automation
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Stop Automation", command=self.stop_automation
        ).pack(side=tk.LEFT, padx=5)

        self.auto_results = tk.Text(frame, height=10)
        scrollbar = ttk.Scrollbar(frame, command=self.auto_results.yview)
        self.auto_results.config(yscrollcommand=scrollbar.set)

        self.auto_results.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu).pack(
            pady=10
        )

    def start_automation(self):
        """
        Start scheduled automation tasks for network scan and password check.
        """
        net_time = self.net_scan_time.get().strip()
        net_target = self.net_scan_target.get().strip()
        pw_time = self.pw_check_time.get().strip()
        pw_password = self.pw_check_password.get().strip()

        if not all([net_time, net_target, pw_time, pw_password]):
            messagebox.showwarning("Error", "All fields are required")
            return

        self.auto_results.delete(1.0, tk.END)
        self.auto_results.insert(tk.END, "Starting automation...\n")

        schedule.clear()
        schedule.every().day.at(net_time).do(self._run_auto_network_scan, net_target)
        schedule.every().day.at(pw_time).do(self._run_auto_password_check, pw_password)

        self.auto_running = True
        Thread(target=self._run_scheduler, daemon=True).start()

        self.auto_results.insert(tk.END, f"Scheduled network scan at {net_time}\n")
        self.auto_results.insert(tk.END, f"Scheduled password check at {pw_time}\n")

    def stop_automation(self):
        """
        Stop all scheduled automation tasks.
        """
        self.auto_running = False
        schedule.clear()
        self.auto_results.insert(tk.END, "\nAutomation stopped\n")

    def _run_scheduler(self):
        """
        Run the scheduler loop to execute pending tasks.
        """
        while getattr(self, "auto_running", False):
            schedule.run_pending()
            time.sleep(1)

    def _run_auto_network_scan(self, target):
        """
        Run automated network scan and display results.
        """
        try:
            results = self.net_scanner.quick_scan(target)
            self.root.after(
                0,
                lambda: self.auto_results.insert(
                    tk.END, f"\nNetwork scan results: {results}\n"
                ),
            )
            self.report_gen.add_network_scan(results)
        except Exception as e:
            self.root.after(
                0,
                lambda: self.auto_results.insert(
                    tk.END, f"\nNetwork scan error: {str(e)}\n"
                ),
            )

    def _run_auto_password_check(self, password):
        """
        Run automated password check and display results.
        """
        try:
            checker = PasswordChecker(password)
            complexity = checker.check_complexity()
            breach = checker.check_breach()

            self.root.after(
                0,
                lambda: self.auto_results.insert(
                    tk.END,
                    f"\nPassword check results:\nPassword: {password}\nComplexity: {complexity}\nBreach: {breach}\n",
                ),
            )

            self.report_gen.add_password_test(password, complexity, breach)
        except Exception as e:
            self.root.after(
                0,
                lambda: self.auto_results.insert(
                    tk.END, f"\nPassword check error: {str(e)}\n"
                ),
            )

    # Report Generation
    def generate_report(self):
        """
        Generate and save a report of all activities.
        """
        try:
            # Ensure reports folder exists
            os.makedirs("reports", exist_ok=True)
            filename = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.report_gen.filename = filename
            self.report_gen.save_as_json()
            messagebox.showinfo("Success", f"Report saved as {filename}.json")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")


if __name__ == "__main__":
    app = CyberSuite()
    app.root.mainloop()
