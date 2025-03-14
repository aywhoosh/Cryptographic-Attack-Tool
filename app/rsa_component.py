"""
RSA Attack UI Components
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time
import threading

from app.ui_component import UIComponent
from attacks.rsa.wiener import wiener_attack, generate_vulnerable_key
from attacks.rsa.franklin_reiter import franklin_reiter_attack, generate_example
from attacks.rsa.pollard_rho import pollard_rho_attack, generate_example as generate_pollard_example

class RSAComponent(UIComponent):
    """RSA Attacks UI Component"""
    
    def __init__(self, parent, root):
        super().__init__(parent, root)
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the RSA attack UI"""
        self.rsa_notebook = ttk.Notebook(self.frame)
        self.rsa_notebook.pack(fill=tk.BOTH, expand=True)
        self.setup_wiener_tab()
        self.setup_franklin_reiter_tab()
        self.setup_pollard_rho_tab()
    
    def setup_wiener_tab(self):
        """Set up the Wiener's attack tab"""
        wiener_frame = ttk.Frame(self.rsa_notebook)
        self.rsa_notebook.add(wiener_frame, text="Wiener's Attack")
        
        desc_frame = tk.LabelFrame(wiener_frame, text="Description", padx=10, pady=10)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        desc_text = scrolledtext.ScrolledText(desc_frame, height=3, width=80, wrap=tk.WORD)
        desc_text.pack(fill=tk.X, padx=5, pady=5)
        desc_text.insert(tk.END, "Wiener's attack exploits small private exponents in RSA. If d < N^0.25/3, the attack can factor N and recover the private key.")
        desc_text.config(state=tk.DISABLED)
        
        input_frame = tk.LabelFrame(wiener_frame, text="Attack Parameters", padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Modulus N:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.wiener_n = tk.Entry(input_frame, width=60)
        self.wiener_n.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(input_frame, text="Public Exponent e:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.wiener_e = tk.Entry(input_frame, width=60)
        self.wiener_e.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        btn_frame = tk.Frame(wiener_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        self.create_button(btn_frame, "Run Wiener's Attack", self.run_wiener_attack, 
                           bg="#3a7ebf", fg="white").pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Generate Example", self.generate_wiener_example,
                           bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        
        results_frame = tk.LabelFrame(wiener_frame, text="Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.wiener_result = self.create_scrolled_text(results_frame, height=10)
        self.wiener_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_franklin_reiter_tab(self):
        """Set up the Franklin-Reiter Related Message Attack tab"""
        fr_frame = ttk.Frame(self.rsa_notebook)
        self.rsa_notebook.add(fr_frame, text="Franklin-Reiter Attack")
        
        # Use pack geometry manager for the main frame with appropriate weights
        fr_frame.pack_propagate(False)
        
        # Create a scrollable frame to contain all components with better dimensions
        canvas = tk.Canvas(fr_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(fr_frame, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)
        
        # Configure canvas and scrollbar properly
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 2))
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.create_window((0, 0), window=scroll_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Improve scroll region calculation
        def configure_scroll_region(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            # Set canvas width to match frame width minus scrollbar width
            canvas.configure(width=fr_frame.winfo_width()-scrollbar.winfo_width()-5)
        
        scroll_frame.bind('<Configure>', configure_scroll_region)
        fr_frame.bind('<Configure>', lambda e: canvas.configure(width=e.width-scrollbar.winfo_width()-5))
        
        # Description section
        desc_frame = tk.LabelFrame(scroll_frame, text="Attack Description", padx=10, pady=10)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        desc_text = scrolledtext.ScrolledText(desc_frame, height=6, width=80, wrap=tk.WORD)
        desc_text.pack(fill=tk.X, padx=5, pady=5)
        desc_text.insert(tk.END, """The Franklin-Reiter related message attack exploits RSA when two related messages are encrypted with the same public key.

Key requirements:
• Two messages with a linear relationship: m₂ = a·m₁ + b
• Both encrypted with the same RSA key
• Small public exponent (typically e=3)

The attack uses polynomial GCD techniques to recover both messages without needing the private key.
This vulnerability demonstrates why proper message padding is essential in RSA implementations.""")
        desc_text.config(state=tk.DISABLED)
        
        # Parameters section - use a notebook to separate inputs
        params_notebook = ttk.Notebook(scroll_frame)
        params_notebook.pack(fill=tk.X, padx=5, pady=5)
        
        # Manual input tab
        manual_frame = ttk.Frame(params_notebook)
        params_notebook.add(manual_frame, text="Manual Input")
        
        input_frame = tk.LabelFrame(manual_frame, text="Attack Parameters", padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # RSA Parameters
        rsa_params_frame = tk.Frame(input_frame)
        rsa_params_frame.pack(fill=tk.X, pady=5)
        
        # First column - Labels
        labels_frame = tk.Frame(rsa_params_frame)
        labels_frame.pack(side=tk.LEFT, padx=5)
        
        tk.Label(labels_frame, text="Modulus (n):", anchor=tk.W).pack(fill=tk.X, pady=5)
        tk.Label(labels_frame, text="Public Exponent (e):", anchor=tk.W).pack(fill=tk.X, pady=5)
        
        # Second column - Entries
        entries_frame = tk.Frame(rsa_params_frame)
        entries_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.fr_n = tk.Entry(entries_frame, width=60)
        self.fr_n.pack(fill=tk.X, pady=5)
        
        e_frame = tk.Frame(entries_frame)
        e_frame.pack(fill=tk.X, pady=5)
        self.fr_e = tk.Entry(e_frame, width=10)
        self.fr_e.pack(side=tk.LEFT)
        self.fr_e.insert(0, "3")
        tk.Label(e_frame, text="  (e=3 is recommended for this attack)", 
                 fg="#666666", font=("Arial", 8)).pack(side=tk.LEFT)
        
        # Horizontal separator
        ttk.Separator(input_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Message relationship parameters
        rel_frame = tk.LabelFrame(input_frame, text="Message Relationship (m₂ = a·m₁ + b)")
        rel_frame.pack(fill=tk.X, pady=5)
        
        coef_frame = tk.Frame(rel_frame)
        coef_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(coef_frame, text="Coefficient (a):").pack(side=tk.LEFT, padx=5)
        self.fr_a = tk.Entry(coef_frame, width=10)
        self.fr_a.pack(side=tk.LEFT, padx=5)
        self.fr_a.insert(0, "2")
        
        tk.Label(coef_frame, text="Constant (b):").pack(side=tk.LEFT, padx=5)
        self.fr_b = tk.Entry(coef_frame, width=10)
        self.fr_b.pack(side=tk.LEFT, padx=5)
        self.fr_b.insert(0, "3")
        
        # Horizontal separator
        ttk.Separator(input_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Ciphertext section
        cipher_frame = tk.LabelFrame(input_frame, text="Encrypted Messages")
        cipher_frame.pack(fill=tk.X, pady=5)
        
        # First ciphertext
        c1_frame = tk.Frame(cipher_frame)
        c1_frame.pack(fill=tk.X, pady=5)
        tk.Label(c1_frame, text="C₁ = E(m₁):").pack(side=tk.LEFT, padx=5)
        self.fr_c1 = tk.Entry(c1_frame, width=50)
        self.fr_c1.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Second ciphertext
        c2_frame = tk.Frame(cipher_frame)
        c2_frame.pack(fill=tk.X, pady=5)
        tk.Label(c2_frame, text="C₂ = E(m₂):").pack(side=tk.LEFT, padx=5)
        self.fr_c2 = tk.Entry(c2_frame, width=50)
        self.fr_c2.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Action buttons
        btn_frame = tk.Frame(scroll_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.fr_run_btn = tk.Button(btn_frame, text="Run Attack", 
                                   command=self.run_franklin_reiter_attack,
                                   bg="#3a7ebf", fg="white", width=15, height=2)
        self.fr_run_btn.pack(side=tk.LEFT, padx=5)
        
        generate_btn = tk.Button(btn_frame, text="Generate Example", 
                               command=self.generate_fr_example,
                               bg="#4caf50", fg="white", width=15, height=2)
        generate_btn.pack(side=tk.LEFT, padx=5)
        
        # Add tooltips to parameters
        self._create_tooltip(self.fr_n, "The RSA modulus n = p*q")
        self._create_tooltip(self.fr_e, "Public exponent (e=3 works best)")
        self._create_tooltip(self.fr_a, "Linear coefficient in m₂ = a·m₁ + b")
        self._create_tooltip(self.fr_b, "Constant term in m₂ = a·m₁ + b")
        self._create_tooltip(self.fr_c1, "First ciphertext C₁ = m₁ᵉ mod n")
        self._create_tooltip(self.fr_c2, "Second ciphertext C₂ = m₂ᵉ mod n")
        self._create_tooltip(generate_btn, "Generate vulnerable example data for testing")
        
        # Progress frame
        progress_frame = tk.Frame(scroll_frame)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Progress bar
        self.fr_progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        self.fr_progress.pack(fill=tk.X, padx=5, pady=5)
        
        # Progress label
        self.fr_status = tk.StringVar()
        self.fr_status.set("Ready to run attack")
        status_label = tk.Label(progress_frame, textvariable=self.fr_status)
        status_label.pack(pady=5)
        
        # Results section
        results_frame = tk.LabelFrame(scroll_frame, text="Attack Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.fr_result = scrolledtext.ScrolledText(results_frame, height=15, wrap=tk.WORD)
        self.fr_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure text tags for formatting
        self.fr_result.tag_configure("heading", font=("Arial", 11, "bold"))
        self.fr_result.tag_configure("success", foreground="#4caf50", font=("Arial", 11, "bold"))
        self.fr_result.tag_configure("error", foreground="#f44336", font=("Arial", 10, "bold"))
        self.fr_result.tag_configure("warning", foreground="#ff9800")
        self.fr_result.tag_configure("info", foreground="#2196f3")
        self.fr_result.tag_configure("value", font=("Courier New", 10))
        
        # Initial instructions
        self.fr_result.insert(tk.END, "Franklin-Reiter Attack Tool\n\n", "heading")
        self.fr_result.insert(tk.END, "Instructions:\n")
        self.fr_result.insert(tk.END, "1. Enter RSA parameters (n, e) and ciphertexts (C₁, C₂)\n")
        self.fr_result.insert(tk.END, "2. Specify the linear relationship between messages (a, b)\n")
        self.fr_result.insert(tk.END, "3. Click 'Run Attack' to recover the original messages\n\n")
        self.fr_result.insert(tk.END, "Alternatively, use the 'Generate Example' button to create vulnerable test data.\n")
    
    def run_franklin_reiter_attack(self):
        """Run Franklin-Reiter related message attack"""
        try:
            # Get parameters from UI
            n_str = self.fr_n.get().strip()
            e_str = self.fr_e.get().strip()
            c1_str = self.fr_c1.get().strip()
            c2_str = self.fr_c2.get().strip()
            a_str = self.fr_a.get().strip()
            b_str = self.fr_b.get().strip()
            
            # Input validation
            if not all([n_str, e_str, c1_str, c2_str, a_str, b_str]):
                messagebox.showerror("Input Error", "Please provide all required parameters")
                return
            
            try:
                n = int(n_str)
                e = int(e_str)
                c1 = int(c1_str)
                c2 = int(c2_str)
                a = int(a_str)
                b = int(b_str)
            except ValueError:
                messagebox.showerror("Input Error", "All parameters must be valid integers")
                return
            
            # Clear previous results and update UI
            self.fr_result.delete(1.0, tk.END)
            self.fr_status.set("Running Franklin-Reiter attack...")
            self.fr_result.insert(tk.END, f"Ciphertext C₁: ", "info")
            self.fr_result.insert(tk.END, f"{c1}\n", "value")
            self.fr_result.insert(tk.END, f"Ciphertext C₂: ", "info")
            self.fr_result.insert(tk.END, f"{c2}\n", "value")
            self.fr_result.insert(tk.END, f"Relationship: m₂ = {a}·m₁ + {b} mod n\n\n", "info")
            self.update_status("Running Franklin-Reiter attack...")
            
            # Run attack in a separate thread
            def run_attack():
                try:
                    start_time = time.time()
                    result = franklin_reiter_attack(n, e, c1, c2, (a, b), callback=self.fr_callback)
                    elapsed_time = time.time() - start_time
                    # Update results on the main thread
                    self.root.after(0, lambda: self.update_fr_results(result, elapsed_time))
                except Exception as ex:
                    self.root.after(0, lambda: self.fr_error(str(ex)))
            
            # Launch attack thread
            threading.Thread(target=run_attack, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
            self.fr_run_btn.config(state=tk.NORMAL)
            self.fr_progress.stop()
            self.update_status("Error occurred during Franklin-Reiter attack")
    
    def fr_callback(self, status, message):
        """Callback to handle Franklin-Reiter attack progress"""
        self.root.after(0, lambda: self.update_fr_progress(status, message))
    
    def update_fr_progress(self, status, message):
        """Update the UI with Franklin-Reiter attack progress"""
        status_map = {
            "start": ("info", "Starting attack"),
            "info": ("info", "Info"),
            "progress": ("info", "Progress"),
            "warning": ("warning", "Warning"),
            "error": ("error", "Error"),
            "failed": ("error", "Failed"),
            "success": ("success", "Success")
        }
        
        tag, prefix = status_map.get(status, ("info", status.capitalize()))
        
        # Update status bar
        if status == "progress":
            self.fr_status.set(f"In progress: {message}")
        else:
            self.fr_status.set(f"{prefix}: {message}")
        
        # Add to log with appropriate formatting
        self.fr_result.insert(tk.END, f"{prefix}: ", tag)
        self.fr_result.insert(tk.END, f"{message}\n")
        self.fr_result.see(tk.END)
    
    def update_fr_results(self, result, elapsed_time):
        """Update the UI with Franklin-Reiter attack results"""
        # Stop progress indicators
        self.fr_progress.stop()
        self.fr_run_btn.config(state=tk.NORMAL)
        
        if result:
            m1, m2 = result
            # Display success message with styling
            self.fr_result.insert(tk.END, "\n╔════════════════════════════════════════╗\n", "success")
            self.fr_result.insert(tk.END, "║         ATTACK SUCCESSFUL!             ║\n", "success")
            self.fr_result.insert(tk.END, "╚════════════════════════════════════════╝\n\n", "success")
            # Display recovered messages
            self.fr_result.insert(tk.END, "Recovered Messages:\n", "heading")
            self.fr_result.insert(tk.END, "First message (m₁): ", "info")
            self.fr_result.insert(tk.END, f"{m1}\n", "value")
            self.fr_result.insert(tk.END, "Second message (m₂): ", "info")
            self.fr_result.insert(tk.END, f"{m2}\n\n", "value")
            
            # Verification
            n = int(self.fr_n.get())
            e = int(self.fr_e.get())
            a = int(self.fr_a.get())
            b = int(self.fr_b.get())
            
            # Verify message relationship
            rel_check = (a * m1 + b) % n == m2
            self.fr_result.insert(tk.END, f"Message relationship: m₂ = {a}·m₁ + {b} mod n\n")
            self.fr_result.insert(tk.END, f"Verification: ", "info")
            if rel_check:
                self.fr_result.insert(tk.END, "✓ Correct\n", "success")
            else:
                self.fr_result.insert(tk.END, "✗ Failed\n", "error")
            
            # Display timing
            self.fr_result.insert(tk.END, f"\nAttack completed in {elapsed_time:.3f} seconds\n")
            self.update_status("Franklin-Reiter attack completed successfully")
        else:
            # Display failure message
            self.fr_result.insert(tk.END, "\n╔════════════════════════════════════════╗\n", "error")
            self.fr_result.insert(tk.END, "║            ATTACK FAILED!              ║\n", "error")
            self.fr_result.insert(tk.END, "╚════════════════════════════════════════╝\n\n", "error")
            # Common reasons for failure
            self.fr_result.insert(tk.END, "Possible reasons for failure:\n", "heading")
            self.fr_result.insert(tk.END, "• The public exponent e is too large (e=3 works best)\n")
            self.fr_result.insert(tk.END, "• Messages are not related as specified\n")
            self.fr_result.insert(tk.END, "• The modulus n is too large for effective computation\n")
            self.fr_result.insert(tk.END, "• Precision loss in polynomial computations\n\n")
            self.fr_result.insert(tk.END, "Try using the example generator to create data that's known to work.\n")
            self.update_status("Franklin-Reiter attack failed")
        
        # Make sure we see the results
        self.fr_result.see(tk.END)
    
    def fr_error(self, error_message):
        """Handle errors during Franklin-Reiter attack"""
        # Stop progress indicators
        self.fr_progress.stop()
        self.fr_run_btn.config(state=tk.NORMAL)
        
        # Display error message
        self.fr_result.insert(tk.END, "\n╔════════════════════════════════════════╗\n", "error")
        self.fr_result.insert(tk.END, "║               ERROR!                   ║\n", "error")
        self.fr_result.insert(tk.END, "╚════════════════════════════════════════╝\n\n", "error")
        self.fr_result.insert(tk.END, f"Error message: {error_message}\n\n", "error")
        self.update_status(f"Error in Franklin-Reiter attack: {error_message}")
        self.fr_result.see(tk.END)
    
    def generate_fr_example(self):
        """Generate example data for Franklin-Reiter attack"""
        try:
            self.update_status("Generating example for Franklin-Reiter attack...")
            
            # Get bit size for key generation
            try:
                bits = int(self.fr_bits.get())
                if bits < 64:
                    bits = 64  # Minimum reasonable size
                elif bits > 512:
                    if messagebox.askyesno("Warning", "Large bit sizes may cause the attack to fail. Continue anyway?"):
                        pass
                    else:
                        bits = 256
            except:
                bits = 256  # Default value
            
            # Generate example data
            n, e, m1, m2, c1, c2, a, b = generate_example(bits, callback=self.fr_callback)
            
            # Update input fields
            self.fr_n.delete(0, tk.END)
            self.fr_n.insert(0, str(n))
            self.fr_e.delete(0, tk.END)
            self.fr_e.insert(0, str(e))
            self.fr_c1.delete(0, tk.END)
            self.fr_c1.insert(0, str(c1))
            self.fr_c2.delete(0, tk.END)
            self.fr_c2.insert(0, str(c2))
            self.fr_a.delete(0, tk.END)
            self.fr_a.insert(0, str(a))
            self.fr_b.delete(0, tk.END)
            self.fr_b.insert(0, str(b))
            
            # Clear and show results
            self.fr_result.delete(1.0, tk.END)
            self.fr_result.insert(tk.END, "Generated Example Data\n\n", "heading")
            self.fr_result.insert(tk.END, "RSA Parameters:\n", "info")
            self.fr_result.insert(tk.END, f"• Modulus n: {n}\n")
            self.fr_result.insert(tk.END, f"• Public exponent e: {e}\n\n")
            self.fr_result.insert(tk.END, "Original Messages:\n", "info")
            self.fr_result.insert(tk.END, f"• First message m₁: {m1}\n")
            self.fr_result.insert(tk.END, f"• Second message m₂: {m2}\n")
            self.fr_result.insert(tk.END, f"• Relationship: m₂ = {a}·m₁ + {b} mod n\n\n")
            self.fr_result.insert(tk.END, "Encrypted Messages:\n", "info")
            self.fr_result.insert(tk.END, f"• Ciphertext C₁: {c1}\n")
            self.fr_result.insert(tk.END, f"• Ciphertext C₂: {c2}\n\n")
            self.fr_result.insert(tk.END, "All input fields have been populated with these values.\n")
            self.fr_result.insert(tk.END, "Click 'Run Attack' to recover the original messages.\n", "success")
            self.update_status("Generated example for Franklin-Reiter attack")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate example: {str(e)}")
            self.update_status("Error generating example")
    
    def setup_pollard_rho_tab(self):
        """Set up the Pollard Rho factorization tab"""
        pr_frame = ttk.Frame(self.rsa_notebook)
        self.rsa_notebook.add(pr_frame, text="Pollard Rho")
        
        # Add scrollable container
        canvas = tk.Canvas(pr_frame)
        scrollbar = ttk.Scrollbar(pr_frame, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.create_window((0, 0), window=scroll_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Description section
        desc_frame = tk.LabelFrame(scroll_frame, text="Description", padx=10, pady=10)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        desc_text = scrolledtext.ScrolledText(desc_frame, height=4, width=80, wrap=tk.WORD)
        desc_text.pack(fill=tk.X, padx=5, pady=5)
        desc_text.insert(tk.END, """Pollard's Rho algorithm is a factorization method that uses a pseudo-random sequence to find factors of a composite number. The algorithm works by detecting cycles in this sequence, similar to the Greek letter ρ (rho).

Key features:
- Space efficient: Only needs to store a few values
- Probabilistic: May need multiple attempts
- Most effective on numbers with small prime factors""")
        desc_text.config(state=tk.DISABLED)
        
        # Input section
        input_frame = tk.LabelFrame(scroll_frame, text="Attack Parameters", padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Number to Factor:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.pr_n = tk.Entry(input_frame, width=60)
        self.pr_n.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(input_frame, text="Maximum Iterations:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.pr_iterations = tk.Entry(input_frame, width=20)
        self.pr_iterations.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.pr_iterations.insert(0, "10000")
        
        # Buttons
        btn_frame = tk.Frame(scroll_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        self.pr_run_btn = self.create_button(btn_frame, "Run Pollard Rho", self.run_pollard_rho, 
                                           bg="#3a7ebf", fg="white")
        self.pr_run_btn.pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Generate Example", self.generate_pollard_rho_example,
                          bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Results section
        results_frame = tk.LabelFrame(scroll_frame, text="Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.pr_result = self.create_scrolled_text(results_frame, height=10)
        self.pr_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure scrolling
        scroll_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    
    def run_wiener_attack(self):
        """Run Wiener's attack with the provided parameters"""
        try:
            n_str = self.wiener_n.get().strip()
            e_str = self.wiener_e.get().strip()
            if not n_str or not e_str:
                messagebox.showerror("Input Error", "Please provide both N and e values")
                return
            try:
                n = int(n_str)
                e = int(e_str)
            except ValueError:
                messagebox.showerror("Input Error", "N and e must be valid integers")
                return
            
            self.wiener_result.delete(1.0, tk.END)
            self.update_status("Running Wiener's attack...")
            
            def run_attack():
                start_time = time.time()
                result = wiener_attack(e, n, callback=self.wiener_callback)
                elapsed_time = time.time() - start_time
                self.root.after(0, lambda: self.update_wiener_results(result, elapsed_time))
            
            threading.Thread(target=run_attack, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error occurred during Wiener's attack")
    
    def wiener_callback(self, status, message):
        """Callback to handle Wiener's attack progress"""
        self.root.after(0, lambda: self.update_wiener_progress(status, message))
    
    def update_wiener_progress(self, status, message):
        """Update the UI with Wiener's attack progress"""
        if status in ["start", "info", "progress"]:
            self.wiener_result.insert(tk.END, f"{message}\n")
        elif status == "success":
            self.wiener_result.insert(tk.END, f"\n{message}\n", "success")
        elif status == "failed":
            self.wiener_result.insert(tk.END, f"\n{message}\n", "error")
        
        self.wiener_result.see(tk.END)
        self.wiener_result.tag_config("success", foreground="green")
        self.wiener_result.tag_config("error", foreground="red")
    
    def generate_wiener_example(self):
        """Generate an example vulnerable to Wiener's attack"""
        try:
            self.update_status("Generating vulnerable RSA key...")
            n, e, d, p, q = generate_vulnerable_key(callback=self.wiener_callback)
            self.wiener_n.delete(0, tk.END)
            self.wiener_n.insert(0, str(n))
            self.wiener_e.delete(0, tk.END)
            self.wiener_e.insert(0, str(e))
            self.wiener_result.delete(1.0, tk.END)
            self.wiener_result.insert(tk.END, "Generated RSA key vulnerable to Wiener's attack:\n\n")
            self.wiener_result.insert(tk.END, f"Modulus N: {n}\n")
            self.wiener_result.insert(tk.END, f"Public exponent e: {e}\n")
            self.wiener_result.insert(tk.END, f"Private exponent d: {d}\n")
            self.wiener_result.insert(tk.END, f"Prime factor p: {p}\n")
            self.wiener_result.insert(tk.END, f"Prime factor q: {q}\n\n")
            self.wiener_result.insert(tk.END, "Click 'Run Wiener's Attack' to recover the private key.\n")
            self.update_status("Generated example key vulnerable to Wiener's attack")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error generating example key")
    
    def update_wiener_results(self, result, elapsed_time):
        """Update the UI with Wiener's attack results"""
        if result:
            d, p, q = result
            self.wiener_result.insert(tk.END, f"Attack successful!\n\n", "success")
            self.wiener_result.insert(tk.END, f"Private exponent d: {d}\n")
            self.wiener_result.insert(tk.END, f"Prime factor p: {p}\n")
            self.wiener_result.insert(tk.END, f"Prime factor q: {q}\n\n")
            self.wiener_result.insert(tk.END, f"RSA key factored in {elapsed_time:.3f} seconds\n")
            self.update_status("Wiener's attack completed successfully")
        else:
            self.wiener_result.insert(tk.END, "Attack failed. The key might not be vulnerable to Wiener's attack.\n")
            self.wiener_result.insert(tk.END, "This attack only works when the private exponent d is small.\n")
            self.update_status("Wiener's attack failed")
    
    def pollard_rho_callback(self, status, data):
        """Callback to handle Pollard's Rho algorithm progress"""
        self.update_pollard_rho_progress(status, data)
    
    def update_pollard_rho_progress(self, status, data):
        """Update the UI with Pollard's Rho algorithm progress"""
        try:
            # Handle message display for different data formats
            if isinstance(data, dict) and "message" in data:
                message = data["message"]
                explanation = data.get("explanation", "")
                if explanation:
                    self.pr_result.insert(tk.END, f"{message} - {explanation}\n")
                else:
                    self.pr_result.insert(tk.END, f"{message}\n")
            elif isinstance(data, str):
                self.pr_result.insert(tk.END, f"{data}\n")
                
            # Handle status-specific styling
            if status == "success":
                if isinstance(data, dict) and "message" in data:
                    self.pr_result.insert(tk.END, f"\n{data['message']}\n", "success")
                else:
                    self.pr_result.insert(tk.END, f"\n{data}\n", "success")
            elif status == "failed":
                if isinstance(data, dict) and "message" in data:
                    self.pr_result.insert(tk.END, f"\n{data['message']}\n", "error")
                else:
                    self.pr_result.insert(tk.END, f"\n{data}\n", "error")
            
            self.pr_result.see(tk.END)
            self.pr_result.tag_config("success", foreground="green", font=("Arial", 10, "bold"))
            self.pr_result.tag_config("error", foreground="red")
        except Exception as e:
            print(f"Error updating UI: {e}")
    
    def run_pollard_rho(self):
        """Run Pollard's Rho factorization algorithm"""
        try:
            n_str = self.pr_n.get().strip()
            iterations_str = self.pr_iterations.get().strip()
            
            if not n_str:
                messagebox.showerror("Input Error", "Please provide the number to factor")
                return
            try:
                n = int(n_str)
                max_iterations = int(iterations_str) if iterations_str else 10000
            except ValueError:
                messagebox.showerror("Input Error", "The number to factor must be a valid integer")
                return
            
            # Clean up UI and prepare for run
            self.pr_result.delete(1.0, tk.END)
            self.pr_run_btn.config(state=tk.DISABLED)
            self.update_status("Running Pollard's Rho algorithm...")
            
            def run_attack():
                try:
                    start_time = time.time()
                    
                    # Run the attack
                    result = pollard_rho_attack(n, max_iterations=max_iterations, callback=self.pollard_rho_callback)
                    elapsed_time = time.time() - start_time
                    
                    # Update results when done
                    self.root.after(0, lambda: self.update_pollard_rho_results(result, elapsed_time))
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Attack error: {str(e)}"))
                    self.root.after(0, lambda: self.pr_run_btn.config(state=tk.NORMAL))
                    
            # Run in background thread
            threading.Thread(target=run_attack, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.pr_run_btn.config(state=tk.NORMAL)
            self.update_status("Error occurred during Pollard's Rho factorization")
    
    def update_pollard_rho_results(self, result, elapsed_time):
        """Update the UI with Pollard's Rho results"""
        self.pr_run_btn.config(state=tk.NORMAL)
        
        if result:
            factors = result
            self.pr_result.insert(tk.END, f"Factorization successful!\n\n", "success")
            self.pr_result.insert(tk.END, f"Number: {self.pr_n.get()}\n")
            self.pr_result.insert(tk.END, "Factors found:\n")
            for i, factor in enumerate(factors, 1):
                self.pr_result.insert(tk.END, f"  Factor {i}: {factor}\n", "factor")
            self.pr_result.insert(tk.END, f"\nFactorization completed in {elapsed_time:.3f} seconds\n")
            self.update_status(f"Factorization completed: found {len(factors)} factors")
        else:
            self.pr_result.insert(tk.END, "Factorization failed. No factors were found.\n", "error")
            self.pr_result.insert(tk.END, "Try increasing the maximum iterations or using a different algorithm.\n")
            self.update_status("Factorization failed")
        
        self.pr_result.tag_config("factor", foreground="blue")
    
    def generate_pollard_rho_example(self):
        """Generate an example for Pollard's Rho factorization"""
        try:
            self.update_status("Generating example for Pollard's Rho factorization...")
            n, factors = generate_pollard_example()
            self.pr_n.delete(0, tk.END)
            self.pr_n.insert(0, str(n))
            self.pr_result.delete(1.0, tk.END)
            
            self.pr_result.insert(tk.END, "Generated example for Pollard's Rho factorization:\n\n")
            self.pr_result.insert(tk.END, f"Number to factor: {n}\n\n")
            self.pr_result.insert(tk.END, "Actual factors (for verification):\n")
            for i, factor in enumerate(factors, 1):
                self.pr_result.insert(tk.END, f"  Factor {i}: {factor}\n")
            self.pr_result.insert(tk.END, "\nClick 'Run Pollard Rho' to find the factors.\n")
            self.update_status("Generated example for Pollard's Rho factorization")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error generating example")
    
    def _create_tooltip(self, widget, text):
        """Create a tooltip for a widget"""
        def show_tooltip(event):
            # Get the widget's coordinates
            x = widget.winfo_rootx() + 20
            y = widget.winfo_rooty() + 20
            
            # Create the tooltip window
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{x}+{y}")
            
            # Configure the tooltip appearance
            if len(text) > 100:  # For long text, make a wider tooltip
                width = min(400, self.root.winfo_width() - 100)  # Limit width to window size
                label = tk.Label(tooltip, text=text, justify=tk.LEFT, wraplength=width,
                                background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                                font=("Arial", "8", "normal"), padx=5, pady=5)
            else:
                label = tk.Label(tooltip, text=text, justify=tk.LEFT,
                                background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                                font=("Arial", "8", "normal"))
            
            label.pack()
            
            def hide_tooltip():
                tooltip.destroy()
            
            widget.tooltip = tooltip
            widget.bind('<Leave>', lambda e: hide_tooltip())
            tooltip.bind('<Leave>', hide_tooltip)
            tooltip.after(10000, lambda: hide_tooltip() if hasattr(widget, 'tooltip') else None)  # Auto-hide tooltip after 10 seconds
            
        widget.bind('<Enter>', show_tooltip)

