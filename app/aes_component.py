"""
AES-CBC Padding Oracle Attack UI Component
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import binascii
import os
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from app.ui_component import UIComponent
from attacks.aes.poc import poc
from attacks.aes.settings import BYTE_NB, key, IV

class Tooltip:
    """Simple tooltip class for tkinter widgets"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip, text=self.text, justify=tk.LEFT,
                         background="#ffffff", relief="solid", borderwidth=1,
                         wraplength=400, padx=4, pady=4)
        label.pack()
    def hide_tooltip(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class AESComponent(UIComponent):
    def __init__(self, parent, root):
        super().__init__(parent, root)  # Properly initialize parent class
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the AES attack UI"""
        # Create main frame using self.frame from parent class
        main_frame = ttk.Frame(self.frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Rest of the UI setup remains the same
        input_frame = ttk.LabelFrame(main_frame, text="Input")
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(input_frame, text="Plaintext:").pack(anchor=tk.W, padx=5, pady=2)
        self.aes_plaintext = scrolledtext.ScrolledText(input_frame, height=3)
        self.aes_plaintext.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(input_frame, text="Ciphertext (hex):").pack(anchor=tk.W, padx=5, pady=2)
        self.aes_ciphertext = scrolledtext.ScrolledText(input_frame, height=3)
        self.aes_ciphertext.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(input_frame, text="IV (hex):").pack(anchor=tk.W, padx=5, pady=2)
        self.iv_entry = ttk.Entry(input_frame)
        self.iv_entry.pack(fill=tk.X, padx=5, pady=2)

        # Add an explanation of the ciphertext generation process
        explanation_frame = ttk.Frame(input_frame)
        explanation_frame.pack(fill=tk.X, padx=5, pady=5)
        explanation_text = "How ciphertext is generated: Your plaintext is padded using PKCS#7 padding, then encrypted using AES-CBC with the key and IV from settings.py. The resulting ciphertext is displayed as hexadecimal."
        explanation_label = ttk.Label(explanation_frame, text=explanation_text, wraplength=500)
        explanation_label.pack(anchor=tk.W)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        # Create blue Generate Sample button 
        self.generate_btn = tk.Button(btn_frame, text="Generate Sample", 
                                    command=self.generate_aes_sample,
                                    background="#007bff", foreground="white",
                                    activebackground="#0069d9", activeforeground="white",
                                    relief=tk.RAISED, padx=10)
        self.generate_btn.pack(side=tk.LEFT, padx=5)
        
        # Create tooltip for generate button
        Tooltip(self.generate_btn, "Generate an AES-CBC encrypted sample using your plaintext or a default message. The encryption uses a fixed key and IV from settings.py.")
        
        # Create green Run Attack button
        self.attack_btn = tk.Button(btn_frame, text="Run Attack", 
                                  command=self.run_aes_attack,
                                  background="#28a745", foreground="white",
                                  activebackground="#218838", activeforeground="white",
                                  relief=tk.RAISED, padx=10)
        self.attack_btn.pack(side=tk.LEFT, padx=5)
        
        # Create tooltip for attack button
        Tooltip(self.attack_btn, "Run the AES-CBC padding oracle attack to recover the plaintext without knowing the key.")

        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        result_frame = ttk.LabelFrame(main_frame, text="Results")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.aes_result = scrolledtext.ScrolledText(result_frame)
        self.aes_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def generate_aes_sample(self):
        """Generate sample AES encrypted data"""
        try:
            self.update_status("Generating sample data...")
            
            plaintext = self.aes_plaintext.get(1.0, tk.END).strip()
            if not plaintext:
                plaintext = "This is a sample secret message for the padding oracle attack demo!"
                self.aes_plaintext.delete(1.0, tk.END)
                self.aes_plaintext.insert(tk.END, plaintext)

            # Create AES cipher
            cipher = AES.new(key, AES.MODE_CBC, IV)
            
            # Pad and encrypt
            padding_length = BYTE_NB - (len(plaintext) % BYTE_NB)
            padded_data = plaintext.encode() + bytes([padding_length] * padding_length)
            ciphertext = cipher.encrypt(padded_data)
            
            # Display results
            self.aes_ciphertext.delete(1.0, tk.END)
            self.aes_ciphertext.insert(tk.END, ciphertext.hex())
            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, IV.hex())
            
            # Show details
            self.aes_result.delete(1.0, tk.END)
            self.aes_result.insert(tk.END, "Generated Sample Data:\n\n")
            self.aes_result.insert(tk.END, f"Original plaintext: {plaintext}\n")
            self.aes_result.insert(tk.END, f"Block size: {BYTE_NB} bytes\n")
            self.aes_result.insert(tk.END, f"Ciphertext (hex): {ciphertext.hex()}\n")
            self.aes_result.insert(tk.END, f"IV (hex): {IV.hex()}\n\n")
            self.aes_result.insert(tk.END, "Encryption Process:\n")
            self.aes_result.insert(tk.END, f"1. Original plaintext: '{plaintext}'\n")
            self.aes_result.insert(tk.END, f"2. Plaintext length: {len(plaintext)} bytes\n")
            self.aes_result.insert(tk.END, f"3. PKCS#7 padding added: {padding_length} bytes of value {padding_length}\n")
            self.aes_result.insert(tk.END, f"4. Padded plaintext (hex): {padded_data.hex()}\n")
            self.aes_result.insert(tk.END, f"5. Encrypted using AES-CBC with fixed key and IV\n")
            self.aes_result.insert(tk.END, f"6. Final ciphertext (hex): {ciphertext.hex()}\n\n")
            self.aes_result.insert(tk.END, "Note: The attack will only have access to the ciphertext and IV.\n")
            
            self.update_status("Sample data generated successfully")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status(f"Error generating sample: {str(e)}")

    def run_aes_attack(self):
        """Run the AES-CBC padding oracle attack"""
        try:
            self.update_status("Running AES-CBC Padding Oracle Attack...")
            self.aes_result.delete(1.0, tk.END)
            
            # Get input data
            ciphertext_hex = self.aes_ciphertext.get(1.0, tk.END).strip()
            if not ciphertext_hex:
                messagebox.showerror("Input Error", "Ciphertext must be provided in hexadecimal format")
                self.update_status("Attack aborted: missing ciphertext")
                return
            
            try:
                ciphertext = bytes.fromhex(ciphertext_hex)
            except ValueError:
                messagebox.showerror("Input Error", "Invalid hexadecimal ciphertext")
                self.update_status("Attack aborted: invalid hex data")
                return
            
            if len(ciphertext) % BYTE_NB != 0:
                messagebox.showerror("Input Error", f"Ciphertext length must be a multiple of {BYTE_NB}")
                self.update_status("Attack aborted: invalid ciphertext length")
                return

            # Run attack
            start_time = time.time()
            try:
                recovered = poc(ciphertext)
                elapsed_time = time.time() - start_time
                
                if recovered:
                    try:
                        result_text = recovered.decode('utf-8', errors='replace')
                        self.aes_result.insert(tk.END, f"Decrypted plaintext:\n{result_text}\n\n")
                    except UnicodeDecodeError:
                        self.aes_result.insert(tk.END, f"Decrypted data (hex):\n{recovered.hex()}\n\n")
                    
                    self.aes_result.insert(tk.END, f"Attack completed in {elapsed_time:.2f} seconds\n")
                    self.aes_result.insert(tk.END, f"Processed {len(ciphertext)} bytes in {len(ciphertext)//BYTE_NB} blocks")
                    self.update_status(f"Attack completed successfully in {elapsed_time:.2f} seconds")
                else:
                    self.aes_result.insert(tk.END, "Attack failed - could not decrypt data\n")
                    self.update_status("Attack failed")
            
            except Exception as e:
                self.aes_result.insert(tk.END, f"Error during attack: {str(e)}\n")
                self.update_status(f"Attack error: {str(e)}")
        
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status(f"Error during attack setup: {str(e)}")
    
    def update_status(self, message):
        """Update status message"""
        self.status_var.set(message)
