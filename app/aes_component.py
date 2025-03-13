"""
AES-CBC Padding Oracle Attack UI Component
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import binascii
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from app.ui_component import UIComponent
from attacks.aes.attack import aes_attack, demonstrate_aes_attack

class AESComponent(UIComponent):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.block_viz_info = None
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the AES attack UI"""
        # Main container with scrollbar
        self.main_canvas = tk.Canvas(self.frame)
        self.main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.main_canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.main_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Inner frame for content
        self.inner_frame = tk.Frame(self.main_canvas)
        self.main_canvas.create_window((0, 0), window=self.inner_frame, anchor=tk.NW, width=self.main_canvas.winfo_width())
        
        # Input frame
        input_frame = tk.LabelFrame(self.inner_frame, text="AES-CBC Padding Oracle Attack Parameters", padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Plaintext to encrypt (for demonstration):").grid(row=0, column=0, sticky=tk.W)
        self.aes_plaintext = self.create_scrolled_text(input_frame, height=2, width=60)
        self.aes_plaintext.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        self.aes_plaintext.insert(tk.END, "This is a secret message for testing the padding oracle attack!")
        
        tk.Label(input_frame, text="Ciphertext (hex):").grid(row=2, column=0, sticky=tk.W)
        self.aes_ciphertext = self.create_scrolled_text(input_frame, height=3, width=60)
        self.aes_ciphertext.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        
        tk.Label(input_frame, text="Initialization Vector (hex):").grid(row=4, column=0, sticky=tk.W)
        self.aes_iv = tk.Entry(input_frame, width=50)
        self.aes_iv.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        
        tk.Label(input_frame, text="Block Size (bytes):").grid(row=6, column=0, sticky=tk.W)
        self.block_size_var = tk.StringVar(value="16")
        tk.OptionMenu(input_frame, self.block_size_var, "16", "32").grid(row=6, column=1, sticky=tk.W)
        
        # Visualization frame
        visual_frame = tk.LabelFrame(self.inner_frame, text="Visualization", padx=10, pady=10)
        visual_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add explanation text
        explanation_text = """
        AES-CBC Padding Oracle Attack Visualization
        ----------------------------------------
        Each block represents 16 bytes of data:
        - IV (Blue): Initialization Vector
        - Data Blocks (Light Blue): Encrypted blocks
        - Last Block (Orange): Contains padding
        
        During the attack:
        - Yellow: Currently testing byte
        - Green: Successfully recovered byte
        - Red: Failed to recover byte (using fallback)
        
        Progress shows both overall completion and current byte recovery status.
        """
        tk.Label(visual_frame, text=explanation_text, justify=tk.LEFT).pack(fill=tk.X, padx=5)
        
        self.aes_canvas = tk.Canvas(visual_frame, width=900, height=200, bg='white')
        self.aes_canvas.pack(fill=tk.X, padx=5, pady=5)
        
        # Status and progress
        status_frame = tk.Frame(visual_frame)
        status_frame.pack(fill=tk.X, padx=5)
        
        tk.Label(status_frame, text="Current Operation:").pack(side=tk.LEFT)
        self.aes_info_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.aes_info_var, anchor=tk.W).pack(side=tk.LEFT, padx=5)
        
        # Two progress bars: overall and current byte
        progress_frame = tk.Frame(visual_frame)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(progress_frame, text="Overall Progress:").grid(row=0, column=0, sticky=tk.W)
        self.aes_progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.aes_progress.grid(row=0, column=1, sticky=tk.EW, padx=5)
        
        tk.Label(progress_frame, text="Current Byte:").grid(row=1, column=0, sticky=tk.W)
        self.byte_progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.byte_progress.grid(row=1, column=1, sticky=tk.EW, padx=5)
        progress_frame.columnconfigure(1, weight=1)
        
        # Buttons
        btn_frame = tk.Frame(self.inner_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        self.create_button(btn_frame, "Run Padding Oracle Attack", self.run_aes_attack,
                           bg='#3a7ebf', fg='white').pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Run Demo Attack", self.run_aes_demo,
                           bg='#4caf50', fg='white').pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Generate Sample Data", self.generate_aes_sample,
                           bg='#ff9800', fg='white').pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Clear Fields", self.clear_fields,
                           bg='#f44336', fg='white').pack(side=tk.LEFT, padx=5)
        
        # Results frame with detailed information
        results_frame = tk.LabelFrame(self.inner_frame, text="Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add explanation for the results
        tk.Label(results_frame, text="Attack Progress and Results:", anchor=tk.W).pack(fill=tk.X, padx=5)
        self.aes_result = self.create_scrolled_text(results_frame, height=12)
        self.aes_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure scroll region when window is resized
        self.inner_frame.bind('<Configure>', self._configure_scroll_region)
        self.main_canvas.bind('<Configure>', self._configure_canvas)
    
    def _configure_scroll_region(self, event):
        """Configure the scroll region of the canvas"""
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
    
    def _configure_canvas(self, event):
        """Update the canvas size when the window is resized"""
        self.main_canvas.itemconfig(self.main_canvas.find_withtag("all")[0], width=event.width)
    
    def clear_fields(self):
        """Clear all input and result fields"""
        self.aes_plaintext.delete(1.0, tk.END)
        self.aes_ciphertext.delete(1.0, tk.END)
        self.aes_iv.delete(0, tk.END)
        self.aes_result.delete(1.0, tk.END)
        self.aes_canvas.delete("all")
        self.aes_info_var.set("Ready")
        self.aes_progress['value'] = 0
        self.update_status("Cleared AES fields")
    
    def run_aes_attack(self):
        """Run the AES-CBC padding oracle attack on provided ciphertext and IV"""
        try:
            self.update_status("Running AES-CBC Padding Oracle Attack...")
            self.aes_result.delete(1.0, tk.END)
            self.aes_progress['value'] = 0
            
            ciphertext_hex = self.aes_ciphertext.get(1.0, tk.END).strip()
            iv_hex = self.aes_iv.get().strip()
            block_size = int(self.block_size_var.get())
            
            if not ciphertext_hex or not iv_hex:
                messagebox.showerror("Input Error", "Ciphertext and IV must be provided in hexadecimal format")
                self.update_status("Attack aborted: missing input")
                return
            
            try:
                ciphertext = binascii.unhexlify(ciphertext_hex)
                iv = binascii.unhexlify(iv_hex)
            except binascii.Error:
                messagebox.showerror("Input Error", "Invalid hexadecimal data provided")
                self.update_status("Attack aborted: invalid hex data")
                return
            
            if len(iv) != block_size:
                messagebox.showerror("Input Error", f"IV must be {block_size} bytes (got {len(iv)})")
                self.update_status("Attack aborted: invalid IV size")
                return
            
            if len(ciphertext) % block_size != 0:
                messagebox.showerror("Input Error", "Ciphertext length must be a multiple of block size")
                self.update_status("Attack aborted: invalid ciphertext length")
                return
            
            self.setup_aes_visualization(len(ciphertext), block_size)
            
            key = b'\x00' * block_size  # Dummy key for demo
            def padding_oracle(test_data):
                try:
                    time.sleep(0.01)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    _ = unpad(cipher.decrypt(test_data), block_size)
                    return True
                except ValueError:
                    return False
            
            start_time = time.time()
            recovered = aes_attack(ciphertext, padding_oracle, iv, block_size, self.aes_visual_callback)
            elapsed_time = time.time() - start_time
            
            if recovered:
                try:
                    result_text = recovered.decode('utf-8', errors='replace')
                    self.aes_result.insert(tk.END, f"Decrypted plaintext:\n{result_text}\n\n")
                except UnicodeDecodeError:
                    self.aes_result.insert(tk.END, f"Decrypted data (hex):\n{recovered.hex()}\n\n")
                self.aes_result.insert(tk.END, f"Raw bytes: {recovered}\n")
                self.aes_result.insert(tk.END, f"Attack completed in {elapsed_time:.2f} seconds\n")
                self.aes_result.insert(tk.END, f"Processed {len(ciphertext)} bytes in {len(ciphertext)//block_size} blocks")
                self.update_status(f"AES attack completed successfully in {elapsed_time:.2f} seconds")
            else:
                self.aes_result.insert(tk.END, "Attack failed - could not decrypt data")
                self.update_status("AES attack failed")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error occurred during AES attack")
    
    def generate_aes_sample(self):
        """Generate sample AES encrypted data for demonstration"""
        try:
            self.update_status("Generating AES sample data...")
            key = get_random_bytes(16)
            iv = get_random_bytes(16)
            block_size = int(self.block_size_var.get())
            
            plaintext = self.aes_plaintext.get(1.0, tk.END).strip()
            if not plaintext:
                plaintext = "This is a sample secret message for the padding oracle attack demo!"
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(plaintext.encode(), block_size)
            ciphertext = cipher.encrypt(padded_data)
            
            self.aes_ciphertext.delete(1.0, tk.END)
            self.aes_ciphertext.insert(tk.END, ciphertext.hex())
            self.aes_iv.delete(0, tk.END)
            self.aes_iv.insert(0, iv.hex())
            
            self.setup_aes_visualization(len(plaintext.encode()), block_size)
            self.aes_result.delete(1.0, tk.END)
            self.aes_result.insert(tk.END, "Generated Sample Data:\n\n")
            self.aes_result.insert(tk.END, f"Original plaintext: {plaintext}\n")
            self.aes_result.insert(tk.END, f"Key (hex): {key.hex()}\n")
            self.aes_result.insert(tk.END, f"IV (hex): {iv.hex()}\n")
            self.aes_result.insert(tk.END, f"Ciphertext (hex): {ciphertext.hex()}\n\n")
            self.aes_result.insert(tk.END, "Note: In a real attack, you only have the ciphertext and IV.\n")
            self.update_status("Sample AES data generated successfully")
            messagebox.showinfo("Sample Data Generated", 
                                "Sample data has been generated and populated in the input fields.\n"
                                "Click 'Run Padding Oracle Attack' to start the attack.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error generating AES sample data")
    
    def run_aes_demo(self):
        """Run a demonstration of the AES-CBC Padding Oracle Attack with visualization"""
        try:
            self.update_status("Running AES-CBC Padding Oracle Attack demonstration...")
            self.aes_result.delete(1.0, tk.END)
            self.aes_progress['value'] = 0
            
            plaintext = self.aes_plaintext.get(1.0, tk.END).strip()
            if not plaintext:
                plaintext = "This is a sample message for demonstration!"
                self.aes_plaintext.delete(1.0, tk.END)
                self.aes_plaintext.insert(tk.END, plaintext)
            
            block_size = int(self.block_size_var.get())
            plaintext_bytes = plaintext.encode('utf-8')
            self.setup_aes_visualization(len(plaintext_bytes), block_size)
            
            original, recovered, encrypt_time, attack_time = demonstrate_aes_attack(
                plaintext_bytes, block_size=block_size, visual_callback=self.aes_visual_callback)
            
            self.aes_result.insert(tk.END, "AES-CBC Padding Oracle Attack Demonstration\n")
            self.aes_result.insert(tk.END, "=" * 50 + "\n\n")
            self.aes_result.insert(tk.END, f"Original plaintext: {original.decode('utf-8', errors='replace')}\n\n")
            if recovered:
                try:
                    self.aes_result.insert(tk.END, f"Recovered plaintext: {recovered.decode('utf-8', errors='replace')}\n\n")
                except UnicodeDecodeError:
                    self.aes_result.insert(tk.END, f"Recovered data (hex): {recovered.hex()}\n\n")
                self.aes_result.insert(tk.END, f"Attack successful: {original == recovered}\n")
            else:
                self.aes_result.insert(tk.END, "Attack failed - could not recover plaintext\n")
            self.aes_result.insert(tk.END, f"\nEncryption time: {encrypt_time:.3f} seconds\n")
            self.aes_result.insert(tk.END, f"Attack time: {attack_time:.3f} seconds\n")
            self.aes_result.insert(tk.END, f"\nProcessed {len(original)} bytes in {(len(original) + block_size - 1) // block_size} blocks\n")
            self.update_status(f"AES demonstration completed in {attack_time:.2f} seconds")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error occurred during AES demonstration")
    
    def setup_aes_visualization(self, plaintext_length, block_size):
        """Prepare the canvas for AES attack visualization"""
        self.aes_canvas.delete("all")
        padding = block_size - (plaintext_length % block_size)
        if padding == 0:
            padding = block_size
        total_length = plaintext_length + padding
        num_blocks = total_length // block_size
        
        block_width = min(850 // (num_blocks + 1), 100)
        block_height = 70
        x0, y0 = 50, 30
        x1, y1 = x0 + block_width, y0 + block_height
        self.aes_canvas.create_rectangle(x0, y0, x1, y1, fill="#e0e0ff", outline="black")
        self.aes_canvas.create_text((x0+x1)//2, (y0+y1)//2, text="IV")
        
        for i in range(num_blocks):
            block_x0 = x0 + (i+1) * (block_width + 10)
            block_x1 = block_x0 + block_width
            block_color = "#ffedcc" if i == num_blocks - 1 else "#e6f5ff"
            self.aes_canvas.create_rectangle(block_x0, y0, block_x1, y1, fill=block_color, outline="black")
            self.aes_canvas.create_text((block_x0+block_x1)//2, (y0+y1)//2, text=f"Block {i+1}")
        
        self.block_viz_info = {
            "block_width": block_width,
            "block_height": block_height,
            "start_x": x0,
            "start_y": y0,
            "spacing": 10,
            "num_blocks": num_blocks,
            "status_y": y0 + block_height + 20
        }
    
    def aes_visual_callback(self, block_idx, byte_idx, found_byte, intermediate_byte, status, message="", progress=0):
        """Enhanced callback to update the visualization during AES attack"""
        if self.block_viz_info is None:
            return
        
        info = self.block_viz_info
        block_width = info["block_width"]
        block_height = info["block_height"]
        status_y = info["status_y"]
        
        # Fix block_idx calculation for visualization
        effective_block_idx = 0 if block_idx is None else block_idx
        if effective_block_idx >= 0:
            block_x = info["start_x"] + (effective_block_idx + 1) * (block_width + info["spacing"])
        else:
            block_x = info["start_x"]
        
        block_y = info["start_y"]
        
        try:
            # Update overall progress
            if status != "complete":
                total_bytes = info["num_blocks"] * 16
                current_byte = block_idx * 16 + (15 - byte_idx) if block_idx is not None and byte_idx is not None else 0
                progress_pct = (current_byte / total_bytes) * 100 if total_bytes > 0 else 0
                self.aes_progress['value'] = progress_pct
            else:
                self.aes_progress['value'] = 100
            
            # Update byte progress
            self.byte_progress['value'] = progress if status == "testing" else 0
            
            self.aes_canvas.delete("status")
            self.aes_canvas.delete("status_text")
            
            # Update status message
            status_msg = ""
            if status == "block_start":
                status_msg = message
                self.aes_canvas.create_rectangle(
                    block_x, block_y,
                    block_x + block_width, block_y + block_height,
                    fill="#fff3e0", outline="black", width=2, tags="status"
                )
            elif status == "byte_start":
                status_msg = message
            elif status == "testing":
                status_msg = f"Testing byte value: {progress}/256"
                if byte_idx is not None:
                    self.aes_canvas.create_rectangle(
                        block_x, block_y + byte_idx * (block_height / 16),
                        block_x + block_width, block_y + (byte_idx + 1) * (block_height / 16),
                        fill="yellow", outline="", tags="status"
                    )
            elif status == "found":
                status_msg = message
                if byte_idx is not None:
                    self.aes_canvas.create_rectangle(
                        block_x, block_y + byte_idx * (block_height / 16),
                        block_x + block_width, block_y + (byte_idx + 1) * (block_height / 16),
                        fill="green", outline="", tags="status"
                    )
                    # Show recovered byte value
                    if found_byte is not None:
                        char_display = chr(found_byte) if 32 <= found_byte <= 126 else '?'
                        self.aes_canvas.create_text(
                            block_x + block_width/2,
                            block_y + (byte_idx + 0.5) * (block_height / 16),
                            text=f"{char_display}",
                            tags="status"
                        )
            elif status == "failed":
                status_msg = message
                if byte_idx is not None:
                    self.aes_canvas.create_rectangle(
                        block_x, block_y + byte_idx * (block_height / 16),
                        block_x + block_width, block_y + (byte_idx + 1) * (block_height / 16),
                        fill="red", outline="", tags="status"
                    )
            elif status == "complete":
                status_msg = message
                self.aes_progress['value'] = 100
                self.byte_progress['value'] = 0
            
            # Update status text
            if status_msg:
                self.aes_info_var.set(status_msg)
                self.aes_canvas.create_text(
                    info["start_x"], status_y,
                    text=status_msg,
                    anchor=tk.W,
                    tags="status_text"
                )
            
            # Update the results text area with detailed information
            if message and status not in ("testing",):
                self.aes_result.insert(tk.END, f"{message}\n")
                self.aes_result.see(tk.END)
            
            self.root.update_idletasks()
        except tk.TclError:
            # Ignore Tcl/Tk errors that might occur during window closing
            pass
        except Exception as e:
            print(f"Visualization error: {e}")
        
        try:
            self.root.update()
        except tk.TclError:
            # Ignore errors during window closing
            pass
