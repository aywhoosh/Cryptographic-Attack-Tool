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
        
        # Buttons - between attack parameters and visualization
        btn_frame = tk.Frame(scroll_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        self.pr_run_btn = self.create_button(btn_frame, "Run Pollard Rho", self.run_pollard_rho, 
                                           bg="#3a7ebf", fg="white")
        self.pr_run_btn.pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Generate Example", self.generate_pollard_rho_example,
                          bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Visualization section - Completely redesigned with multiple parts
        vis_frame = tk.LabelFrame(scroll_frame, text="Algorithm Visualization", padx=10, pady=10)
        vis_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Progress indicator
        progress_frame = tk.Frame(vis_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.pr_status = tk.StringVar(value="Ready")
        tk.Label(progress_frame, textvariable=self.pr_status, width=70, anchor="w").pack(side=tk.LEFT, padx=5)
        
        self.pr_iteration_label = tk.StringVar(value="Iteration: 0")
        tk.Label(progress_frame, textvariable=self.pr_iteration_label).pack(side=tk.RIGHT, padx=5)
        
        # Canvas for main visualization
        self.pr_canvas = tk.Canvas(vis_frame, width=800, height=250, bg='white', highlightthickness=1, highlightbackground="#cccccc")
        self.pr_canvas.pack(fill=tk.X, padx=5, pady=5)
        
        # Step navigation controls
        step_control_frame = tk.Frame(vis_frame)
        step_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Store visualization state
        self.visualization_history = []
        self.current_step = 0
        self._auto_play_id = None
        
        # Detailed iteration info
        self.iter_info_frame = tk.LabelFrame(vis_frame, text="Current Iteration Details", padx=10, pady=10)
        self.iter_info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        detail_grid = tk.Frame(self.iter_info_frame)
        detail_grid.pack(fill=tk.X, padx=5, pady=5)
        
        # Row 1: Function and values
        tk.Label(detail_grid, text="Function:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.pr_function = tk.StringVar(value="f(x) = x² + c mod n")
        tk.Label(detail_grid, textvariable=self.pr_function, width=30).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Label(detail_grid, text="Constant c:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.pr_c_value = tk.StringVar(value="1")
        tk.Label(detail_grid, textvariable=self.pr_c_value, width=10).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Row 2: Tortoise and Hare
        tk.Label(detail_grid, text="Tortoise value:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.pr_tortoise = tk.StringVar(value="0")
        tk.Label(detail_grid, textvariable=self.pr_tortoise).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Label(detail_grid, text="Hare value:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.pr_hare = tk.StringVar(value="0")
        tk.Label(detail_grid, textvariable=self.pr_hare).grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Row 3: GCD calculation
        tk.Label(detail_grid, text="GCD Calculation:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.pr_gcd_calc = tk.StringVar(value="gcd(|T-H|, n) = gcd(0, n) = n")
        tk.Label(detail_grid, textvariable=self.pr_gcd_calc, width=40).grid(row=2, column=1, columnspan=3, sticky=tk.W, padx=5, pady=2)
        
        # Step navigation controls
        self.step_first_btn = tk.Button(step_control_frame, text="⏮ First", command=self.visualization_first_step, state=tk.DISABLED)
        self.step_first_btn.pack(side=tk.LEFT, padx=2)
        
        self.step_prev_btn = tk.Button(step_control_frame, text="◀ Previous", command=self.visualization_prev_step, state=tk.DISABLED)
        self.step_prev_btn.pack(side=tk.LEFT, padx=2)
        
        # Step indicator
        self.step_indicator = tk.StringVar(value="Step 0/0")
        step_label = tk.Label(step_control_frame, textvariable=self.step_indicator, width=15)
        step_label.pack(side=tk.LEFT, padx=10)
        
        self.step_next_btn = tk.Button(step_control_frame, text="Next ▶", command=self.visualization_next_step, state=tk.DISABLED)
        self.step_next_btn.pack(side=tk.LEFT, padx=2)
        
        self.step_last_btn = tk.Button(step_control_frame, text="Last ⏭", command=self.visualization_last_step, state=tk.DISABLED)
        self.step_last_btn.pack(side=tk.LEFT, padx=2)
        
        # Auto-play controls
        auto_frame = tk.Frame(step_control_frame)
        auto_frame.pack(side=tk.RIGHT, padx=10)
        
        self.auto_play_var = tk.BooleanVar(value=False)
        self.auto_play_btn = tk.Button(auto_frame, text="▶ Auto-Play", command=self.toggle_auto_play, state=tk.DISABLED)
        self.auto_play_btn.pack(side=tk.LEFT, padx=5)
        
        # Speed control
        tk.Label(auto_frame, text="Speed:").pack(side=tk.LEFT)
        self.speed_var = tk.DoubleVar(value=1.0)
        speed_scale = ttk.Scale(auto_frame, variable=self.speed_var, from_=0.1, to=3.0, length=100)
        speed_scale.pack(side=tk.LEFT, padx=5)
        
        # Results section
        results_frame = tk.LabelFrame(scroll_frame, text="Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.pr_result = self.create_scrolled_text(results_frame, height=10)
        self.pr_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Progress bar below results
        self.pr_progress = ttk.Progressbar(results_frame, orient=tk.HORIZONTAL, mode="determinate")
        self.pr_progress.pack(fill=tk.X, padx=5, pady=5)
        
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

    def pollard_rho_callback(self, status, data):
        """Callback to handle Pollard's Rho algorithm progress"""
        # This runs in a background thread, so schedule UI updates on the main thread
        if status == "progress" and isinstance(data, dict):
            # Make a deep copy to avoid data race issues
            history_item = {key: data[key] for key in data}
            
            # Add step number to easily track steps
            history_item["step_number"] = len(self.visualization_history) + 1
            
            # Store in visualization history
            self.visualization_history.append(history_item)
            
            # Update UI on the main thread
            step_num = len(self.visualization_history)
            self.root.after(0, lambda: self.update_step_counter(step_num))
            self.root.after(0, lambda: self.update_progress_bar(step_num))
            
            # If this is a factor-found step, highlight it
            if "gcd" in data and data.get("n", 1) > data.get("gcd", 1) > 1:
                self.root.after(0, lambda: self.highlight_factor_found(step_num, data))
        
        self.root.after(0, lambda: self.update_pollard_rho_progress(status, data))

    def update_progress_bar(self, steps_completed):
        """Update the progress bar based on steps completed"""
        try:
            max_iter = int(self.pr_iterations.get())
            progress = min(100, (steps_completed / max_iter) * 100)
            self.pr_progress['value'] = progress
        except (ValueError, ZeroDivisionError):
            self.pr_progress['value'] = 0

    def update_step_counter(self, step_num):
        """Update the step counter display"""
        self.current_step = step_num
        self.step_indicator.set(f"Step {step_num}/{step_num}")
        self.enable_step_controls()

    def highlight_factor_found(self, step_num, data):
        """Highlight when a factor is found"""
        gcd = data.get("gcd", 0)
        n = data.get("n", 1)
        if 1 < gcd < n:
            # Add special highlighting to results
            self.pr_result.insert(tk.END, f"\n🌟 FACTOR FOUND at step {step_num}: {gcd} is a factor of {n} 🌟\n", "success")
            self.pr_result.see(tk.END)
            
            # Jump to this step in visualization
            self.current_step = step_num
            self.step_indicator.set(f"Step {step_num}/{step_num}")
            self.render_visualization_step(data)

    def render_visualization_step(self, data):
        """Render a visualization step with detailed information"""
        if not data:
            return
        
        # Clear previous visualization
        self.pr_canvas.delete("all")
        
        # Extract data from the current step
        iteration = data.get("iteration", 0)
        tortoise = data.get("tortoise", 0)
        hare = data.get("hare", 0)
        gcd = data.get("gcd", 0)
        c = data.get("c", 0)
        n = data.get("n", 0)
        history = data.get("history", [])
        
        # Update status and iteration information
        self.pr_iteration_label.set(f"Iteration: {iteration}")
        self.pr_status.set(f"Computing GCD({abs(tortoise-hare)}, {n}) = {gcd}")
        
        # Update detailed information
        self.pr_function.set(f"f(x) = x² + {c} mod {n}")
        self.pr_c_value.set(f"{c}")
        self.pr_tortoise.set(f"{tortoise}")
        self.pr_hare.set(f"{hare}")
        self.pr_gcd_calc.set(f"gcd(|{tortoise}-{hare}|, {n}) = gcd({abs(tortoise-hare)}, {n}) = {gcd}")
        
        # Calculate canvas dimensions
        width = self.pr_canvas.winfo_width() or 800
        height = self.pr_canvas.winfo_height() or 250
        
        # Draw title and explanation
        self.pr_canvas.create_text(width//2, 20, text=f"Pollard's Rho - Step {self.current_step}/{len(self.visualization_history)}", 
                               font=("Arial", 12, "bold"))
        
        # Draw state machine diagram - circles representing sequence states
        circle_y = height // 2
        circle_radius = 30
        center_x = width // 2
        max_circles = min(15, len(history) + 1)  # Limit to prevent overcrowding
        
        # Calculate the sequence values to show (most recent ones)
        if history and len(history) > 0:
            show_history = history[-max_circles:] if len(history) > max_circles else history
            
            # Draw sequence elements as a chain
            seq_start_x = center_x - ((len(show_history) - 1) * circle_radius)
            
            # First, draw the connecting lines between nodes
            for i in range(len(show_history) - 1):
                x1 = seq_start_x + i * 2 * circle_radius
                x2 = x1 + 2 * circle_radius
                
                # Draw standard connection
                self.pr_canvas.create_line(x1 + circle_radius, circle_y, x2 - circle_radius, circle_y, 
                                       arrow=tk.LAST, width=2)
            
            # Then draw the nodes themselves (to appear on top of lines)
            for i, step in enumerate(show_history):
                x = seq_start_x + i * 2 * circle_radius
                
                # For tortoise positions
                t_value = step.get("tortoise", 0)
                t_color = "#90EE90"  # Light green
                
                # Special coloring for the current tortoise
                if i == len(show_history) - 1:
                    t_color = "#3CB371"  # Medium sea green
                
                # Draw tortoise circle
                self.pr_canvas.create_oval(x - circle_radius, circle_y - 50 - circle_radius, 
                                       x + circle_radius, circle_y - 50 + circle_radius, 
                                       fill=t_color, outline="black")
                self.pr_canvas.create_text(x, circle_y - 50, text=f"{t_value}", font=("Arial", 10))
                self.pr_canvas.create_text(x, circle_y - 50 - circle_radius - 10, text="Tortoise", font=("Arial", 8))
                
                # For hare positions (offset below)
                h_value = step.get("hare", 0)
                h_color = "#FFB6C1"  # Light pink
                
                # Special coloring for the current hare
                if i == len(show_history) - 1:
                    h_color = "#FF6347"  # Tomato
                
                # Draw hare circle
                self.pr_canvas.create_oval(x - circle_radius, circle_y + 50 - circle_radius, 
                                       x + circle_radius, circle_y + 50 + circle_radius, 
                                       fill=h_color, outline="black")
                self.pr_canvas.create_text(x, circle_y + 50, text=f"{h_value}", font=("Arial", 10))
                self.pr_canvas.create_text(x, circle_y + 50 + circle_radius + 10, text="Hare", font=("Arial", 8))
        
        # Add additional information and GCD calculation
        info_y = height - 40
        gcd_color = "green" if 1 < gcd < n else "black"
        self.pr_canvas.create_text(center_x, info_y, text=f"Current GCD = {gcd}", 
                               fill=gcd_color, font=("Arial", 11, "bold"))
        
        # Show cycle detection status
        if 1 < gcd < n:
            self.pr_canvas.create_text(center_x, info_y + 20, 
                                   text=f"Factor found! {gcd} is a factor of {n}", 
                                   fill="green", font=("Arial", 12, "bold"))
        
        # Force immediate update
        self.root.update_idletasks()

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
                # Update the visualization to the last step
                self.visualization_last_step()
                
            elif status == "failed":
                if isinstance(data, dict) and "message" in data:
                    self.pr_result.insert(tk.END, f"\n{data['message']}\n", "error")
                else:
                    self.pr_result.insert(tk.END, f"\n{data}\n", "error")
            
            self.pr_result.see(tk.END)
            self.pr_result.tag_config("success", foreground="green", font=("Arial", 10, "bold"))
            self.pr_result.tag_config("error", foreground="red")
            
        except Exception as e:
            print(f"Visualization error: {e}")

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
            self.pr_canvas.delete("all")
            self.pr_status.set("Running Pollard's Rho algorithm...")
            self.pr_progress['value'] = 0
            self.pr_run_btn.config(state=tk.DISABLED)
            
            # Reset visualization history and controls
            self.visualization_history = []
            self.current_step = 0
            self.step_indicator.set("Step 0/0")
            self.disable_step_controls()
            self.pr_function.set("f(x) = x² + c mod n")
            self.pr_c_value.set("0")
            self.pr_tortoise.set("0")
            self.pr_hare.set("0")
            self.pr_gcd_calc.set("gcd(|T-H|, n) = ?")
            
            def run_attack():
                try:
                    start_time = time.time()
                    
                    # Display initial state
                    self.root.after(0, lambda: self.initialize_visualization(n))
                    
                    # Run the attack with callback for visualization
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
            self.pr_status.set("Error occurred")
            self.pr_run_btn.config(state=tk.NORMAL)
            self.update_status("Error occurred during Pollard's Rho factorization")

    def visualization_first_step(self):
        """Go to the first step in the visualization"""
        if not self.visualization_history:
            return
        
        self.current_step = 1
        self.step_indicator.set(f"Step {self.current_step}/{len(self.visualization_history)}")
        self.render_visualization_step(self.visualization_history[0])
        self.update_step_buttons()

    def visualization_prev_step(self):
        """Go to the previous step in the visualization"""
        if not self.visualization_history or self.current_step <= 1:
            return
        
        self.current_step -= 1
        self.step_indicator.set(f"Step {self.current_step}/{len(self.visualization_history)}")
        self.render_visualization_step(self.visualization_history[self.current_step - 1])
        self.update_step_buttons()

    def visualization_next_step(self):
        """Go to the next step in the visualization"""
        if not self.visualization_history or self.current_step >= len(self.visualization_history):
            return
        
        self.current_step += 1
        self.step_indicator.set(f"Step {self.current_step}/{len(self.visualization_history)}")
        self.render_visualization_step(self.visualization_history[self.current_step - 1])
        self.update_step_buttons()

    def visualization_last_step(self):
        """Go to the last step in the visualization"""
        if not self.visualization_history:
            return
        
        self.current_step = len(self.visualization_history)
        self.step_indicator.set(f"Step {self.current_step}/{len(self.visualization_history)}")
        self.render_visualization_step(self.visualization_history[-1])
        self.update_step_buttons()

    def toggle_auto_play(self):
        """Toggle auto-play mode for the visualization"""
        if self.auto_play_var.get():
            self.auto_play_var.set(False)
            self.auto_play_btn.config(text="▶ Auto")
            # Cancel any scheduled auto-play steps
            if hasattr(self, '_auto_play_id') and self._auto_play_id:
                try:
                    self.root.after_cancel(self._auto_play_id)
                except Exception:
                    pass  # Handle the case where the ID is invalid
                self._auto_play_id = None
        else:
            self.auto_play_var.set(True)
            self.auto_play_btn.config(text="⏹ Stop")
            # Start auto-play
            self.auto_play_step()

    def auto_play_step(self):
        """Advance to the next step in auto-play mode"""
        if not self.auto_play_var.get():
            return
        
        # Go to next step
        if self.current_step < len(self.visualization_history):
            self.visualization_next_step()
            # Calculate delay based on speed setting
            delay = int(1000 / self.speed_var.get())
            # Schedule next step
            self._auto_play_id = self.root.after(delay, self.auto_play_step)
        else:
            # Reached the end, stop auto-play
            self.auto_play_var.set(False)
            self.auto_play_btn.config(text="▶ Auto")

    def update_step_buttons(self):
        """Update the state of step buttons based on current position"""
        if not self.visualization_history:
            self.disable_step_controls()
            return
        
        # Enable/disable first and previous buttons
        if self.current_step <= 1:
            self.step_first_btn.config(state=tk.DISABLED)
            self.step_prev_btn.config(state=tk.DISABLED)
        else:
            self.step_first_btn.config(state=tk.NORMAL)
            self.step_prev_btn.config(state=tk.NORMAL)
        
        # Enable/disable next and last buttons
        if self.current_step >= len(self.visualization_history):
            self.step_next_btn.config(state=tk.DISABLED)
            self.step_last_btn.config(state=tk.DISABLED)
        else:
            self.step_next_btn.config(state=tk.NORMAL)
            self.step_last_btn.config(state=tk.NORMAL)
        
        # Always enable auto-play if we have history
        self.auto_play_btn.config(state=tk.NORMAL)

    def enable_step_controls(self):
        """Enable step controls when visualization history is available"""
        if self.visualization_history:
            self.auto_play_btn.config(state=tk.NORMAL)
            self.update_step_buttons()

    def disable_step_controls(self):
        """Disable all step controls"""
        self.step_first_btn.config(state=tk.DISABLED)
        self.step_prev_btn.config(state=tk.DISABLED)
        self.step_next_btn.config(state=tk.DISABLED)
        self.step_last_btn.config(state=tk.DISABLED)
        self.auto_play_btn.config(state=tk.DISABLED)
        self.auto_play_var.set(False)

    def initialize_visualization(self, n):
        """Initialize the visualization area with a clean slate"""
        self.pr_canvas.delete("all")
        width = self.pr_canvas.winfo_width() or 800
        height = self.pr_canvas.winfo_height() or 250
        
        # Draw title and starting text
        self.pr_canvas.create_text(width//2, height//2, text=f"Initializing Pollard's Rho Algorithm to Factor {n}", 
                               font=("Arial", 12, "bold"))
        self.pr_canvas.create_text(width//2, height//2 + 30, text="Algorithm starts with tortoise=2 and hare=2",
                               font=("Arial", 10))
        self.pr_canvas.create_text(width//2, height//2 + 60, text="For each step: tortoise = f(tortoise), hare = f(f(hare))",
                               font=("Arial", 10))
        
        # Force update
        self.root.update_idletasks()

    def update_pollard_rho_results(self, result, elapsed_time):
        """Update the UI with Pollard's Rho results"""
        self.pr_progress['value'] = 100
        self.pr_run_btn.config(state=tk.NORMAL)
        
        if result:
            factors = result
            self.pr_result.insert(tk.END, f"Factorization successful!\n\n", "success")
            self.pr_result.insert(tk.END, f"Number: {self.pr_n.get()}\n")
            self.pr_result.insert(tk.END, "Factors found:\n")
            for i, factor in enumerate(factors, 1):
                self.pr_result.insert(tk.END, f"  Factor {i}: {factor}\n", "factor")
            self.pr_result.insert(tk.END, f"\nFactorization completed in {elapsed_time:.3f} seconds\n")
            self.pr_result.insert(tk.END, f"Total steps: {len(self.visualization_history)}\n")
            self.pr_status.set(f"Factorization completed: found {len(factors)} factors")
        else:
            self.pr_result.insert(tk.END, "Factorization failed. No factors were found.\n", "error")
            self.pr_result.insert(tk.END, "Try increasing the maximum iterations or using a different algorithm.\n")
            self.pr_status.set("Factorization failed")
        
        self.pr_result.tag_config("factor", foreground="blue")
        self.update_status(f"Pollard Rho completed in {elapsed_time:.2f} seconds")

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
