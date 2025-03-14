"""
Main Application Class for Cryptographic Attack Tool
"""
import tkinter as tk
from tkinter import ttk, messagebox, Menu, scrolledtext
import platform
import os

from app.aes_component import AESComponent
from app.rsa_component import RSAComponent
from app.vigenere_component import VigenereComponent

class CryptoAttackTool:
    """Main application class for the Cryptographic Attack Tool"""
    def __init__(self, root):
        self.root = root 
        self.root.title("Cryptographic Attack Tool")
        self.root.geometry("1000x700")
        
        # Try to load icon from multiple possible locations
        icon_paths = [
            "app/assets/icon.ico",
            "assets/icon.ico",
            os.path.join(os.path.dirname(__file__), "assets", "icon.ico")
        ]
        
        if platform.system() == "Windows":
            for icon_path in icon_paths:
                try:
                    if os.path.exists(icon_path):
                        self.root.iconbitmap(icon_path)
                        break
                except Exception:
                    continue  # Try next path if current fails
        
        self.configure_style()
        self.create_heading()
        self.create_menu()
        self.create_notebook()
        self.create_status_bar()
        self.add_attack_tabs()
        
        # Expose status_var and other methods for UI components
        self.root.status_var = self.status_var
    
    # Wrapper methods to pass to components
    def event_generate(self, event_name, data=None):
        self.root.event_generate(event_name, data=data)
    
    def bind(self, event, handler):
        self.root.bind(event, handler)
    
    def update(self):
        self.root.update()
    
    def after(self, delay, callback=None):
        return self.root.after(delay, callback)
    
    def create_heading(self):
        """Create the blue heading bar"""
        heading_frame = tk.Frame(self.root, bg="#2c3e50", height=40)
        heading_frame.pack(fill=tk.X, side=tk.TOP)
        heading_frame.pack_propagate(False)
        
        heading_label = tk.Label(
            heading_frame, 
            text="Cryptographic Attack Visualization - by Ayush Jain and Abhilash Ramesh Seth",
            fg="white",
            bg="#2c3e50",
            font=("Helvetica", 12, "bold")
        )
        heading_label.pack(expand=True)
    
    def configure_style(self):
        """Configure the application style"""
        style = ttk.Style()
        if platform.system() == "Windows":
            style.theme_use("vista")
        elif platform.system() == "Darwin":
            style.theme_use("aqua")
        else:
            style.theme_use("clam")
        
        style.configure("TNotebook", background="#f0f0f0")
        style.configure("TNotebook.Tab", padding=[10, 5], font=("Helvetica", 10))
        style.configure("TButton", padding=6)
        style.configure("TLabel", font=("Helvetica", 10))
    
    def create_menu(self):
        """Create the application menu bar"""
        self.menu_bar = Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        # File menu
        file_menu = Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Help menu
        help_menu = Menu(self.menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        
        # Testing menu (for running self-tests)
        test_menu = Menu(self.menu_bar, tearoff=0)
        test_menu.add_command(label="Run Self-Tests", command=self.run_self_tests)
        self.menu_bar.add_cascade(label="Testing", menu=test_menu)
    
    def create_notebook(self):
        """Create the main notebook interface"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_status_bar(self):
        """Create the status bar at the bottom of the application"""
        status_frame = tk.Frame(self.root, bd=1, relief=tk.SUNKEN)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_label = tk.Label(status_frame, textvariable=self.status_var, anchor=tk.W, padx=10, pady=3)
        status_label.pack(side=tk.LEFT, fill=tk.X)
    
    def add_attack_tabs(self):
        """Add tabs for different cryptographic attacks"""
        # AES tab
        aes_frame = ttk.Frame(self.notebook)
        self.notebook.add(aes_frame, text="AES-CBC Attack")
        self.aes_component = AESComponent(aes_frame, self)
        
        # RSA attacks tab
        rsa_frame = ttk.Frame(self.notebook)
        self.notebook.add(rsa_frame, text="RSA Attacks")
        self.rsa_component = RSAComponent(rsa_frame, self)
        
        # Vigenère cipher attacks
        vigenere_frame = ttk.Frame(self.notebook)
        self.notebook.add(vigenere_frame, text="Vigenère Attacks")
        self.vigenere_component = VigenereComponent(vigenere_frame, self)
        
        # Placeholder for future attacks
        placeholder_frame = ttk.Frame(self.notebook)
        self.notebook.add(placeholder_frame, text="More Attacks")
        ttk.Label(placeholder_frame, text="Additional attacks will be added in future versions.").pack(padx=20, pady=20)
    
    def update_status(self, text):
        """Update the status bar with text"""
        self.status_var.set(text)
    
    def show_documentation(self):
        """Display detailed documentation and usage instructions"""
        doc_text = (
            "Cryptographic Attack Tool Documentation\n\n"
            "This tool demonstrates several cryptographic attacks for educational purposes.\n\n"
            "AES-CBC Padding Oracle Attack:\n"
            "  - Enter the plaintext for demonstration, or generate sample data.\n"
            "  - Provide the ciphertext and IV (in hexadecimal) if running your own attack.\n"
            "  - Use the visualization panel to see progress.\n\n"
            "RSA Attacks:\n"
            "  - Wiener’s Attack: Enter modulus N and public exponent e. Generate an example if needed.\n"
            "  - Franklin-Reiter Attack: Provide two ciphertexts along with the linear relation parameters.\n"
            "  - Pollard Rho: Enter the composite number to factor; an example can be generated.\n\n"
            "Vigenère Cipher Attacks (Kasiski Examination):\n"
            "  - Enter the ciphertext (alphabetic only) and set minimum sequence length and max key length.\n"
            "  - The tool will attempt to deduce the key and show possible decryptions.\n\n"
            "Use the Testing menu to run self-tests on each module. For further details, please refer to the user guide."
        )
        doc_win = tk.Toplevel(self.root)
        doc_win.title("Documentation")
        doc_win.geometry("600x500")
        st = scrolledtext.ScrolledText(doc_win, wrap=tk.WORD)
        st.insert(tk.END, doc_text)
        st.config(state=tk.DISABLED)
        st.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def show_about(self):
        """Show information about the application"""
        about_text = (
            "Cryptographic Attack Tool\n\n"
            "A demonstration of various cryptographic attacks for educational and research purposes.\n\n"
            "Developed by Ayush Jain and Abhilash Ramesh Seth as part of the ISS Lab project."
        )
        messagebox.showinfo("About", about_text)
    
    def run_self_tests(self):
        """Run a series of self-tests for the attacks and display results"""
        results = []
        try:
            # Import example generators and test functions from each attack module
            from attacks.aes.attack import demonstrate_aes_attack
            from attacks.rsa.wiener import generate_vulnerable_key, wiener_attack
            from attacks.vigenere.kasiski import kasiski_examination
            import time

            # AES Test
            plaintext = b"Test message for AES padding oracle attack."
            _, recovered, etime, atime = demonstrate_aes_attack(plaintext, 16)
            aes_success = (plaintext == recovered)
            results.append(f"AES Test: {'Success' if aes_success else 'Failure'} (Encrypt: {etime:.3f}s, Attack: {atime:.3f}s)")
            
            # RSA Wiener Test (generate a vulnerable key and try to recover d)
            n, e, d, p, q = generate_vulnerable_key()
            res = wiener_attack(e, n)
            rsa_success = res is not None and res[0] == d
            results.append(f"RSA Wiener Test: {'Success' if rsa_success else 'Failure'} (Recovered d: {res[0] if res else 'N/A'})")
            
            # Vigenère Kasiski Test
            sample_text = ("THEVIGENERECIPHERISASIMPLEPOLYALPHABETICSUBSTITUTIONENCRYPTIONMETHOD" * 2)
            # Encrypt with a known key for testing:
            key = "CRYPTO"
            def vigenere_encrypt(plaintext, key):
                ciphertext = []
                key_length = len(key)
                for i, char in enumerate(plaintext):
                    if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                        p = ord(char) - ord('A')
                        k = ord(key[i % key_length]) - ord('A')
                        c = (p + k) % 26
                        ciphertext.append(chr(c + ord('A')))
                    else:
                        ciphertext.append(char)
                return ''.join(ciphertext)
            cipher_test = vigenere_encrypt(sample_text, key)
            kasiski_res = kasiski_examination(cipher_test)
            vig_success = kasiski_res is not None and kasiski_res[2][0][0] == key
            results.append(f"Vigenère Kasiski Test: {'Success' if vig_success else 'Failure'} (Key: {kasiski_res[2][0][0] if kasiski_res else 'N/A'})")
        except Exception as e:
            results.append(f"Error during self-tests: {str(e)}")
        
        # Show results in a new window
        test_win = tk.Toplevel(self.root)
        test_win.title("Self-Test Results")
        test_win.geometry("500x300")
        st = scrolledtext.ScrolledText(test_win, wrap=tk.WORD)
        st.insert(tk.END, "\n".join(results))
        st.config(state=tk.DISABLED)
        st.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoAttackTool(root)
    root.mainloop()
