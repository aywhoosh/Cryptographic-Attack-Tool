"""
RSA Attack UI Components
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import binascii
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
        
        desc_frame = tk.LabelFrame(fr_frame, text="Description", padx=10, pady=10)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        desc_text = scrolledtext.ScrolledText(desc_frame, height=3, width=80, wrap=tk.WORD)
        desc_text.pack(fill=tk.X, padx=5, pady=5)
        desc_text.insert(tk.END, "The Franklin-Reiter attack works when two related messages are encrypted with the same RSA key. If M2 = a*M1 + b, both ciphertexts can be used to recover the messages.")
        desc_text.config(state=tk.DISABLED)
        
        input_frame = tk.LabelFrame(fr_frame, text="Attack Parameters", padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Modulus N:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.fr_n = tk.Entry(input_frame, width=60)
        self.fr_n.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(input_frame, text="Public Exponent e:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.fr_e = tk.Entry(input_frame, width=60)
        self.fr_e.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(input_frame, text="Ciphertext C1:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.fr_c1 = tk.Entry(input_frame, width=60)
        self.fr_c1.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(input_frame, text="Ciphertext C2:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.fr_c2 = tk.Entry(input_frame, width=60)
        self.fr_c2.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(input_frame, text="a (M2 = a*M1 + b):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.fr_a = tk.Entry(input_frame, width=20)
        self.fr_a.grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)
        self.fr_a.insert(0, "1")
        
        tk.Label(input_frame, text="b:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        self.fr_b = tk.Entry(input_frame, width=20)
        self.fr_b.grid(row=5, column=1, sticky=tk.W, padx=5, pady=5)
        self.fr_b.insert(0, "1")
        
        btn_frame = tk.Frame(fr_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        self.create_button(btn_frame, "Run Franklin-Reiter Attack", self.run_franklin_reiter_attack, 
                           bg="#3a7ebf", fg="white").pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Generate Example", self.generate_fr_example,
                           bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        
        results_frame = tk.LabelFrame(fr_frame, text="Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.fr_result = self.create_scrolled_text(results_frame, height=10)
        self.fr_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_pollard_rho_tab(self):
        """Set up the Pollard Rho factorization tab"""
        pr_frame = ttk.Frame(self.rsa_notebook)
        self.rsa_notebook.add(pr_frame, text="Pollard Rho")
        
        desc_frame = tk.LabelFrame(pr_frame, text="Description", padx=10, pady=10)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        desc_text = scrolledtext.ScrolledText(desc_frame, height=3, width=80, wrap=tk.WORD)
        desc_text.pack(fill=tk.X, padx=5, pady=5)
        desc_text.insert(tk.END, """Pollard's rho algorithm is a factorization method useful for finding small factors of large composite numbers. It is particularly effective when N has factors close to sqrt(N).""")
        desc_text.config(state=tk.DISABLED)
        
        input_frame = tk.LabelFrame(pr_frame, text="Attack Parameters", padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Number to Factor:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.pr_n = tk.Entry(input_frame, width=60)
        self.pr_n.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(input_frame, text="Maximum Iterations:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.pr_iterations = tk.Entry(input_frame, width=20)
        self.pr_iterations.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.pr_iterations.insert(0, "10000")
        
        progress_frame = tk.Frame(pr_frame)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        self.pr_progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, mode="indeterminate", length=400)
        self.pr_progress.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        self.pr_status = tk.StringVar(value="Ready")
        tk.Label(progress_frame, textvariable=self.pr_status).pack(side=tk.RIGHT, padx=5)
        
        btn_frame = tk.Frame(pr_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        self.pr_run_btn = self.create_button(btn_frame, "Run Pollard Rho", self.run_pollard_rho, 
                                              bg="#3a7ebf", fg="white")
        self.pr_run_btn.pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Generate Example", self.generate_pollard_rho_example,
                           bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        
        results_frame = tk.LabelFrame(pr_frame, text="Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.pr_result = self.create_scrolled_text(results_frame, height=10)
        self.pr_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
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
            self.wiener_result.insert(tk.END, f"Attack successful!\n\n")
            self.wiener_result.insert(tk.END, f"Private exponent d: {d}\n")
            self.wiener_result.insert(tk.END, f"Prime factor p: {p}\n")
            self.wiener_result.insert(tk.END, f"Prime factor q: {q}\n\n")
            self.wiener_result.insert(tk.END, f"RSA key factored in {elapsed_time:.3f} seconds\n")
            self.update_status("Wiener's attack completed successfully")
        else:
            self.wiener_result.insert(tk.END, "Attack failed. The key might not be vulnerable to Wiener's attack.\n")
            self.wiener_result.insert(tk.END, "This attack only works when the private exponent d is small.\n")
            self.update_status("Wiener's attack failed")

    def run_franklin_reiter_attack(self):
        """Run Franklin-Reiter related message attack"""
        try:
            n_str = self.fr_n.get().strip()
            e_str = self.fr_e.get().strip()
            c1_str = self.fr_c1.get().strip()
            c2_str = self.fr_c2.get().strip()
            a_str = self.fr_a.get().strip()
            b_str = self.fr_b.get().strip()
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
            
            self.fr_result.delete(1.0, tk.END)
            self.update_status("Running Franklin-Reiter attack...")
            
            def run_attack():
                start_time = time.time()
                result = franklin_reiter_attack(n, e, c1, c2, (a, b), callback=self.fr_callback)
                elapsed_time = time.time() - start_time
                self.root.after(0, lambda: self.update_fr_results(result, elapsed_time))
            
            threading.Thread(target=run_attack, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error occurred during Franklin-Reiter attack")

    def fr_callback(self, status, message):
        """Callback to handle Franklin-Reiter attack progress"""
        self.root.after(0, lambda: self.update_fr_progress(status, message))

    def update_fr_progress(self, status, message):
        """Update the UI with Franklin-Reiter attack progress"""
        if status in ["start", "info", "progress"]:
            self.fr_result.insert(tk.END, f"{message}\n")
        elif status == "warning":
            self.fr_result.insert(tk.END, f"Warning: {message}\n", "warning")
        elif status == "verify":
            self.fr_result.insert(tk.END, f"\nVerification:\n{message}\n")
        elif status == "success":
            self.fr_result.insert(tk.END, f"\n{message}\n", "success")
        elif status == "failed":
            self.fr_result.insert(tk.END, f"\n{message}\n", "error")
        self.fr_result.see(tk.END)
        self.fr_result.tag_config("success", foreground="green")
        self.fr_result.tag_config("error", foreground="red")
        self.fr_result.tag_config("warning", foreground="orange")

    def generate_fr_example(self):
        """Generate example data for Franklin-Reiter attack"""
        try:
            self.update_status("Generating example for Franklin-Reiter attack...")
            n, e, m1, m2, c1, c2, a, b = generate_example()
            
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
            
            # Show results
            self.fr_result.delete(1.0, tk.END)
            self.fr_result.insert(tk.END, "Generated example for Franklin-Reiter attack:\n\n")
            self.fr_result.insert(tk.END, f"Modulus n = {n}\n")
            self.fr_result.insert(tk.END, f"Public exponent e = {e}\n")
            self.fr_result.insert(tk.END, f"First message m1 = {m1}\n")
            self.fr_result.insert(tk.END, f"Second message m2 = {m2}\n")
            self.fr_result.insert(tk.END, f"First ciphertext c1 = {c1}\n")
            self.fr_result.insert(tk.END, f"Second ciphertext c2 = {c2}\n")
            self.fr_result.insert(tk.END, f"Relationship: m2 = {a}·m1 + {b}\n\n")
            self.fr_result.insert(tk.END, "Click 'Run Franklin-Reiter Attack' to recover the messages.\n")
            
            self.update_status("Generated example for Franklin-Reiter attack")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
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
        
        # Progress section
        progress_frame = tk.LabelFrame(scroll_frame, text="Progress", padx=10, pady=10)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.pr_iteration_label = tk.StringVar(value="Current iteration: 0")
        tk.Label(progress_frame, textvariable=self.pr_iteration_label).pack(fill=tk.X, padx=5)
        
        self.pr_progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, mode="determinate", length=400)
        self.pr_progress.pack(fill=tk.X, padx=5, pady=5)
        
        self.pr_status = tk.StringVar(value="Ready")
        tk.Label(progress_frame, textvariable=self.pr_status).pack(fill=tk.X, padx=5)
        
        # Visual trace section
        visual_frame = tk.LabelFrame(scroll_frame, text="Algorithm Trace", padx=10, pady=10)
        visual_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.pr_canvas = tk.Canvas(visual_frame, width=800, height=200, bg='white')
        self.pr_canvas.pack(fill=tk.X, padx=5, pady=5)
        
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
        self.pr_result = self.create_scrolled_text(results_frame, height=15)
        self.pr_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure scrolling
        scroll_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

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
            
            self.pr_result.delete(1.0, tk.END)
            self.pr_canvas.delete("all")
            self.pr_status.set("Running Pollard's Rho algorithm...")
            self.pr_progress['value'] = 0
            self.pr_run_btn.config(state=tk.DISABLED)
            
            def run_attack():
                start_time = time.time()
                result = pollard_rho_attack(n, max_iterations=max_iterations, callback=self.pollard_rho_callback)
                elapsed_time = time.time() - start_time
                self.root.after(0, lambda: self.update_pollard_rho_results(result, elapsed_time))
            
            threading.Thread(target=run_attack, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.pr_status.set("Error occurred")
            self.pr_run_btn.config(state=tk.NORMAL)
            self.update_status("Error occurred during Pollard's Rho factorization")

    def pollard_rho_callback(self, status, data):
        """Callback to handle Pollard's Rho algorithm progress"""
        self.root.after(0, lambda: self.update_pollard_rho_progress(status, data))

    def update_pollard_rho_progress(self, status, data):
        """Update the UI with Pollard's Rho algorithm progress"""
        if status == "progress":
            iteration = data.get("iteration", 0)
            tortoise = data.get("tortoise", 0)
            hare = data.get("hare", 0)
            gcd = data.get("gcd", 0)
            c = data.get("c", 0)
            
            # Update progress indicators
            max_iter = int(self.pr_iterations.get())
            progress = (iteration / max_iter) * 100
            self.pr_progress['value'] = progress
            self.pr_iteration_label.set(f"Iteration {iteration}, using c={c}")
            
            # Update visualization
            self.pr_canvas.delete("all")
            width = 800
            height = 200
            
            # Draw number line
            self.pr_canvas.create_line(50, height//2, width-50, height//2)
            
            # Draw tortoise and hare positions
            n = int(self.pr_n.get())
            tortoise_x = 50 + (tortoise * (width-100)) // n
            hare_x = 50 + (hare * (width-100)) // n
            
            self.pr_canvas.create_oval(tortoise_x-5, height//2-20, tortoise_x+5, height//2-10, fill="green")
            self.pr_canvas.create_text(tortoise_x, height//2-30, text=f"T={tortoise}")
            
            self.pr_canvas.create_oval(hare_x-5, height//2+10, hare_x+5, height//2+20, fill="red")
            self.pr_canvas.create_text(hare_x, height//2+30, text=f"H={hare}")
            
            # Show GCD value
            self.pr_canvas.create_text(width//2, height-20, text=f"Current GCD = {gcd}")
            
        elif status in ["start", "info", "progress"]:
            self.pr_result.insert(tk.END, f"{data}\n")
        elif status == "success":
            self.pr_result.insert(tk.END, f"\n{data}\n", "success")
        elif status == "failed":
            self.pr_result.insert(tk.END, f"\n{data}\n", "error")
        
        self.pr_result.see(tk.END)
        self.pr_result.tag_config("success", foreground="green")
        self.pr_result.tag_config("error", foreground="red")

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
            
            self.pr_result.delete(1.0, tk.END)
            self.pr_status.set("Running Pollard's Rho algorithm...")
            self.pr_progress.start()
            self.pr_run_btn.config(state=tk.DISABLED)
            
            def run_attack():
                start_time = time.time()
                result = pollard_rho_attack(n, max_iterations)
                elapsed_time = time.time() - start_time
                self.root.after(0, lambda: self.update_pollard_rho_results(result, elapsed_time))
            
            threading.Thread(target=run_attack, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.pr_status.set("Error occurred")
            self.pr_progress.stop()
            self.pr_run_btn.config(state=tk.NORMAL)
            self.update_status("Error occurred during Pollard's Rho factorization")
    
    def update_pollard_rho_results(self, result, elapsed_time):
        """Update the UI with Pollard's Rho results"""
        self.pr_progress.stop()
        self.pr_run_btn.config(state=tk.NORMAL)
        if result:
            factors = result
            self.pr_result.insert(tk.END, f"Factorization successful!\n\n")
            self.pr_result.insert(tk.END, f"Number: {self.pr_n.get()}\n")
            self.pr_result.insert(tk.END, "Factors:\n")
            for i, factor in enumerate(factors, 1):
                self.pr_result.insert(tk.END, f"  Factor {i}: {factor}\n")
            self.pr_result.insert(tk.END, f"\nFactorization completed in {elapsed_time:.3f} seconds\n")
            self.pr_status.set("Factorization completed")
            self.update_status("Pollard's Rho factorization completed successfully")
        else:
            self.pr_result.insert(tk.END, "Factorization failed. No factors were found.\n")
            self.pr_result.insert(tk.END, "Try increasing the maximum iterations or using a different algorithm.\n")
            self.pr_status.set("Factorization failed")
            self.update_status("Pollard's Rho factorization failed")
    
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
            self.pr_status.set("Example generated")
            self.update_status("Generated example for Pollard's Rho factorization")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error generating example")
