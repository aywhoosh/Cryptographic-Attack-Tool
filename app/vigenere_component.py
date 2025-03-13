"""
Vigenère Cipher Attack UI Component
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import string
from tkinter.font import Font

from app.ui_component import UIComponent
from attacks.vigenere.kasiski import kasiski_examination, vigenere_encrypt, decrypt_vigenere

# English letter frequencies for frequency analysis
ENGLISH_FREQS = {
    'E': 0.1249, 'T': 0.0928, 'A': 0.0804, 'O': 0.0764, 'I': 0.0757,
    'N': 0.0723, 'S': 0.0651, 'R': 0.0628, 'H': 0.0505, 'L': 0.0407,
    'D': 0.0382, 'C': 0.0334, 'U': 0.0273, 'M': 0.0251, 'F': 0.0240,
    'P': 0.0214, 'G': 0.0187, 'W': 0.0168, 'Y': 0.0166, 'B': 0.0148,
    'V': 0.0105, 'K': 0.0054, 'X': 0.0023, 'J': 0.0016, 'Q': 0.0012,
    'Z': 0.0009
}

class VigenereComponent(UIComponent):
    def __init__(self, parent, root):
        super().__init__(parent, root)
        self.setup_ui()

    def setup_ui(self):
        """Set up the Vigenère attacks UI with proper scrolling"""
        # Main container with scrollbar
        self.main_canvas = tk.Canvas(self.frame)
        self.main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        main_scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.main_canvas.yview)
        main_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.main_canvas.configure(yscrollcommand=main_scrollbar.set)

        # Inner frame for content
        self.inner_frame = tk.Frame(self.main_canvas)
        self.main_canvas.create_window((0, 0), window=self.inner_frame, anchor=tk.NW)

        # Add notebook to inner frame
        self.vigenere_notebook = ttk.Notebook(self.inner_frame)
        self.vigenere_notebook.pack(fill=tk.BOTH, expand=True)

        self.setup_kasiski_tab()
        self.setup_frequency_tab()

        # Configure scrolling
        self.inner_frame.bind('<Configure>', self._configure_scroll_region)
        self.main_canvas.bind('<Configure>', self._configure_canvas)

    def _configure_scroll_region(self, event):
        """Configure the scroll region of the canvas"""
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))

    def _configure_canvas(self, event):
        """Update the canvas size when the window is resized"""
        canvas_width = event.width - 4  # Account for borders
        self.main_canvas.itemconfig(self.main_canvas.find_withtag("all")[0], width=canvas_width)
        # Update inner frame width
        self.inner_frame.configure(width=canvas_width)
        # Update notebook width
        self.vigenere_notebook.configure(width=canvas_width)

    def setup_kasiski_tab(self):
        # Create frame with minimum size
        kasiski_frame = ttk.Frame(self.vigenere_notebook, height=600)  # Set minimum height
        kasiski_frame.pack_propagate(False)  # Prevent frame from shrinking below minimum size
        self.vigenere_notebook.add(kasiski_frame, text="Kasiski Examination")
        
        # Add container with scrollbar for the entire tab
        tab_canvas = tk.Canvas(kasiski_frame)
        tab_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tab_scrollbar = ttk.Scrollbar(kasiski_frame, orient=tk.VERTICAL, command=tab_canvas.yview)
        tab_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        tab_canvas.configure(yscrollcommand=tab_scrollbar.set)

        # Content frame - set initial width to match canvas
        content_frame = tk.Frame(tab_canvas)
        canvas_window = tab_canvas.create_window((0, 0), window=content_frame, anchor=tk.NW)

        # Update content frame width when canvas resizes
        def update_content_width(event):
            tab_canvas.itemconfig(canvas_window, width=event.width)
        tab_canvas.bind('<Configure>', update_content_width)

        # Description section
        desc_frame = tk.LabelFrame(content_frame, text="Description", padx=10, pady=10)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        desc_text = scrolledtext.ScrolledText(desc_frame, height=3, width=80, wrap=tk.WORD)
        desc_text.pack(fill=tk.X, padx=5, pady=5)
        desc_text.insert(tk.END, "The Kasiski examination is a method of breaking Vigenère ciphers. It looks for repeated sequences in the ciphertext to determine the key length, and then uses frequency analysis on each key position to find the key.")
        desc_text.config(state=tk.DISABLED)

        # Input section
        input_frame = tk.LabelFrame(content_frame, text="Attack Parameters", padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        # Create a two-column layout for input/output
        input_columns = ttk.Frame(input_frame)
        input_columns.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W+tk.E)
        input_columns.columnconfigure(0, weight=1)
        input_columns.columnconfigure(1, weight=1)
        
        # Left column - input
        left_col = ttk.Frame(input_columns)
        left_col.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W+tk.E+tk.N)
        tk.Label(left_col, text="Encrypted Text:").pack(anchor=tk.W)
        self.kasiski_ciphertext = scrolledtext.ScrolledText(left_col, height=6, width=40)
        self.kasiski_ciphertext.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Right column - quick decrypt test
        right_col = ttk.Frame(input_columns)
        right_col.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E+tk.N)
        
        test_frame = ttk.LabelFrame(right_col, text="Quick Decryption Test")
        test_frame.pack(fill=tk.BOTH, expand=True)
        
        key_frame = ttk.Frame(test_frame)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(key_frame, text="Test Key:").pack(side=tk.LEFT)
        self.test_key = ttk.Entry(key_frame, width=15)
        self.test_key.pack(side=tk.LEFT, padx=5)
        self.create_button(key_frame, "Decrypt", self.quick_decrypt_test, bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        
        tk.Label(test_frame, text="Decryption Result:").pack(anchor=tk.W, padx=5)
        self.test_result = scrolledtext.ScrolledText(test_frame, height=4, width=40)
        self.test_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Parameters frame below the columns
        params_frame = tk.Frame(input_frame)
        params_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)

        # Parameter inputs (unchanged)
        tk.Label(params_frame, text="Min Sequence Length:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.kasiski_min_len = tk.Entry(params_frame, width=5)
        self.kasiski_min_len.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.kasiski_min_len.insert(0, "3")

        tk.Label(params_frame, text="Max Key Length:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.kasiski_max_len = tk.Entry(params_frame, width=5)
        self.kasiski_max_len.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        self.kasiski_max_len.insert(0, "10")

        tk.Label(params_frame, text="Language:").grid(row=0, column=4, sticky=tk.W, padx=5, pady=5)
        self.kasiski_lang = ttk.Combobox(params_frame, width=10)
        self.kasiski_lang.grid(row=0, column=5, sticky=tk.W, padx=5, pady=5)
        self.kasiski_lang['values'] = ('English', 'French', 'German', 'Spanish')
        self.kasiski_lang.current(0)

        # Buttons frame
        btn_frame = tk.Frame(content_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=10)
        self.kasiski_run_btn = self.create_button(
            btn_frame, "Run Kasiski Analysis", self.run_kasiski_analysis, bg="#3a7ebf", fg="white")
        self.kasiski_run_btn.pack(side=tk.LEFT, padx=5)
        self.create_button(
            btn_frame, "Generate Example", self.generate_vigenere_example, bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        self.create_button(
            btn_frame, "Clear", self.clear_kasiski, bg="#f44336", fg="white").pack(side=tk.LEFT, padx=5)

        # Progress frame
        progress_frame = tk.Frame(content_frame)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        self.kasiski_progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=400, mode="determinate")
        self.kasiski_progress.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        self.kasiski_status = tk.StringVar(value="Ready")
        tk.Label(progress_frame, textvariable=self.kasiski_status).pack(side=tk.RIGHT, padx=5)

        # Results section with tables - set minimum size and let it expand
        results_frame = tk.LabelFrame(content_frame, text="Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, ipady=100)  # Add minimum internal padding

        # Configure weights for proper expansion
        content_frame.grid_rowconfigure(0, weight=1)
        content_frame.grid_columnconfigure(0, weight=1)

        # Create a notebook for different result views
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Key Analysis Tab with Table - configure grid weights
        key_frame = ttk.Frame(self.results_notebook)
        key_frame.grid_columnconfigure(0, weight=1)
        key_frame.grid_rowconfigure(0, weight=1)
        self.results_notebook.add(key_frame, text="Key Analysis")

        # Create table for key analysis
        self.key_tree = ttk.Treeview(key_frame, columns=("Rank", "Key", "Score"), show="headings", height=10)
        self.key_tree.grid(row=0, column=0, sticky="nsew")
        self.key_tree.heading("Rank", text="Rank")
        self.key_tree.heading("Key", text="Key")
        self.key_tree.heading("Score", text="Score")
        self.key_tree.column("Rank", width=50)
        self.key_tree.column("Key", width=100)
        self.key_tree.column("Score", width=100)

        key_scroll = ttk.Scrollbar(key_frame, orient=tk.VERTICAL, command=self.key_tree.yview)
        key_scroll.grid(row=0, column=1, sticky="ns")
        self.key_tree.configure(yscrollcommand=key_scroll.set)

        # Decryption Tab - configure grid weights
        decrypt_frame = ttk.Frame(self.results_notebook)
        decrypt_frame.grid_columnconfigure(0, weight=1)
        decrypt_frame.grid_rowconfigure(0, weight=1)
        self.results_notebook.add(decrypt_frame, text="Decryption")

        # Create table for decryption results
        self.decrypt_tree = ttk.Treeview(decrypt_frame, columns=("Key", "Plaintext"), show="headings", height=10)
        self.decrypt_tree.grid(row=0, column=0, sticky="nsew")
        self.decrypt_tree.heading("Key", text="Key")
        self.decrypt_tree.heading("Plaintext", text="Decrypted Text")
        self.decrypt_tree.column("Key", width=100)
        self.decrypt_tree.column("Plaintext", width=500)

        decrypt_scroll = ttk.Scrollbar(decrypt_frame, orient=tk.VERTICAL, command=self.decrypt_tree.yview)
        decrypt_scroll.grid(row=0, column=1, sticky="ns")
        self.decrypt_tree.configure(yscrollcommand=decrypt_scroll.set)

        # Analysis Tab - configure grid weights
        analysis_frame = ttk.Frame(self.results_notebook)
        analysis_frame.grid_columnconfigure(0, weight=1)
        analysis_frame.grid_rowconfigure(0, weight=1)
        self.results_notebook.add(analysis_frame, text="Detailed Analysis")

        self.analysis_text = scrolledtext.ScrolledText(analysis_frame, height=15)
        self.analysis_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Add Verification Tab
        verify_frame = ttk.Frame(self.results_notebook)
        verify_frame.grid_columnconfigure(0, weight=1)
        verify_frame.grid_columnconfigure(1, weight=1)
        verify_frame.grid_rowconfigure(1, weight=1)
        self.results_notebook.add(verify_frame, text="Verify/Decrypt")
        
        # Create verification controls section
        control_frame = ttk.Frame(verify_frame)
        control_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        ttk.Label(control_frame, text="Key:").pack(side=tk.LEFT, padx=5, pady=5)
        self.verify_key = ttk.Entry(control_frame, width=20)
        self.verify_key.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.create_button(control_frame, "Decrypt", self.decrypt_with_key, 
                          bg="#3a7ebf", fg="white").pack(side=tk.LEFT, padx=5, pady=5)
        
        self.create_button(control_frame, "Use Selected Key", self.use_selected_key, 
                          bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5, pady=5)
        
        # Create side-by-side comparison view
        ttk.Label(verify_frame, text="Original Ciphertext:").grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        ttk.Label(verify_frame, text="Decrypted Plaintext:").grid(row=1, column=1, sticky="nw", padx=5, pady=5)
        
        self.verify_ciphertext = scrolledtext.ScrolledText(verify_frame, height=15, width=40)
        self.verify_ciphertext.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        
        self.verify_plaintext = scrolledtext.ScrolledText(verify_frame, height=15, width=40)
        self.verify_plaintext.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)
        
        # Configure scroll region for tab
        content_frame.bind('<Configure>', lambda e: tab_canvas.configure(
            scrollregion=tab_canvas.bbox("all")))

    def update_kasiski_results(self, result, ciphertext, elapsed_time):
        """Update the UI with Kasiski examination results using tables"""
        self.kasiski_run_btn.config(state=tk.NORMAL)
        self.kasiski_progress['value'] = 100
        self.kasiski_status.set("Analysis complete")

        # Clear previous results
        for item in self.key_tree.get_children():
            self.key_tree.delete(item)
        for item in self.decrypt_tree.get_children():
            self.decrypt_tree.delete(item)
        self.analysis_text.delete(1.0, tk.END)

        if result:
            likely_key_length, key_analysis, possible_keys, decryptions = result

            # Update key analysis table
            for i, (key, score) in enumerate(possible_keys[:10], 1):
                self.key_tree.insert("", tk.END, values=(i, key, f"{score:.2f}"))

            # Update decryption table
            for key, _ in possible_keys[:5]:
                plaintext = vigenere_encrypt(ciphertext, key)
                display_text = f"{plaintext[:100]}..." if len(plaintext) > 100 else plaintext
                self.decrypt_tree.insert("", tk.END, values=(key, display_text))

            # Update detailed analysis
            self.analysis_text.insert(tk.END, f"Most likely key length: {likely_key_length}\n\n")
            self.analysis_text.insert(tk.END, "Key Length Analysis:\n")
            for length, factors in key_analysis.items():
                self.analysis_text.insert(tk.END, f"Length {length}: {factors} factors\n")

            self.analysis_text.insert(tk.END, f"\nAnalysis completed in {elapsed_time:.3f} seconds\n")
            self.analysis_text.insert(tk.END, f"\nCiphertext statistics:\n")
            self.analysis_text.insert(tk.END, f"Length: {len(ciphertext)} characters\n")

            if likely_key_length > 0:
                self.analysis_text.insert(tk.END, f"\nCharacter frequency by position:\n")
                for i in range(likely_key_length):
                    column = ciphertext[i::likely_key_length]
                    freq = ''.join(sorted(set(column)))
                    self.analysis_text.insert(tk.END, f"Position {i + 1}: {freq}\n")

            self.update_status("Kasiski examination completed successfully")
        else:
            self.analysis_text.insert(tk.END, "Analysis failed. Could not determine key length or possible keys.\n")
            self.analysis_text.insert(tk.END, "Try adjusting the parameters or using a different attack method.\n")
            self.update_status("Kasiski examination failed")

    def setup_frequency_tab(self):
        """Set up the frequency analysis tab with interactive analysis tools"""
        freq_frame = ttk.Frame(self.vigenere_notebook)
        self.vigenere_notebook.add(freq_frame, text="Frequency Analysis")
        
        # Add container with scrollbar
        canvas = tk.Canvas(freq_frame)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(freq_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        canvas.configure(yscrollcommand=scrollbar.set)
        content_frame = tk.Frame(canvas)
        canvas_window = canvas.create_window((0, 0), window=content_frame, anchor=tk.NW)
        
        # Update content frame width when canvas resizes
        def update_content_width(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind('<Configure>', update_content_width)
        
        # Description section
        desc_frame = tk.LabelFrame(content_frame, text="Frequency Analysis Description", padx=10, pady=10)
        desc_frame.pack(fill=tk.X, padx=5, pady=5)
        desc_text = scrolledtext.ScrolledText(desc_frame, height=3, width=80, wrap=tk.WORD)
        desc_text.pack(fill=tk.X, padx=5, pady=5)
        desc_text.insert(tk.END, "Frequency analysis exploits the fact that certain letters appear more frequently in languages. "
                         "In Vigenère ciphers, analyzing letter frequencies for each key position can reveal the key.")
        desc_text.config(state=tk.DISABLED)
        
        # Input section
        input_frame = tk.LabelFrame(content_frame, text="Analysis Input", padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="Ciphertext:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.freq_ciphertext = scrolledtext.ScrolledText(input_frame, height=4, width=80)
        self.freq_ciphertext.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        
        params_frame = tk.Frame(input_frame)
        params_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        tk.Label(params_frame, text="Assumed Key Length:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.freq_key_length = ttk.Combobox(params_frame, width=5)
        self.freq_key_length.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.freq_key_length['values'] = tuple(range(1, 16))
        self.freq_key_length.current(4)  # Default to 5
        
        tk.Label(params_frame, text="Position to Analyze:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.freq_position = ttk.Combobox(params_frame, width=5)
        self.freq_position.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        self.freq_position['values'] = tuple(range(1, 6))  # Updated when key length changes
        self.freq_position.current(0)
        
        # Update position dropdown when key length changes
        def update_positions(*args):
            try:
                key_len = int(self.freq_key_length.get())
                self.freq_position['values'] = tuple(range(1, key_len + 1))
                if int(self.freq_position.get()) > key_len:
                    self.freq_position.current(0)
            except ValueError:
                pass
        
        self.freq_key_length.bind('<<ComboboxSelected>>', update_positions)
        
        # Buttons
        btn_frame = tk.Frame(input_frame)
        btn_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        self.create_button(btn_frame, "Analyze Frequencies", self.run_frequency_analysis, 
                          bg="#3a7ebf", fg="white").pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Use Current Ciphertext", self.copy_to_frequency, 
                          bg="#4caf50", fg="white").pack(side=tk.LEFT, padx=5)
        self.create_button(btn_frame, "Clear", self.clear_frequency, 
                          bg="#f44336", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Chart display area - Use a frame to hold the chart canvas
        chart_frame = tk.LabelFrame(content_frame, text="Letter Frequency Chart", padx=10, pady=10)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.freq_canvas = tk.Canvas(chart_frame, bg="white", height=300)
        self.freq_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Results section
        results_frame = tk.LabelFrame(content_frame, text="Analysis Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tk.Label(results_frame, text="Suggested Key Characters:").pack(anchor=tk.W, padx=5, pady=5)
        self.freq_results = tk.Entry(results_frame, width=30)
        self.freq_results.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(results_frame, text="Analysis Details:").pack(anchor=tk.W, padx=5, pady=5)
        self.freq_details = scrolledtext.ScrolledText(results_frame, height=8)
        self.freq_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure scroll region
        content_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    def run_frequency_analysis(self):
        """Run frequency analysis on the ciphertext"""
        try:
            ciphertext = self.freq_ciphertext.get(1.0, tk.END).strip()
            clean_text = ''.join(c for c in ciphertext.upper() if c in string.ascii_uppercase)
            
            if not clean_text:
                messagebox.showerror("Input Error", "Please provide ciphertext to analyze")
                return
            try:
                key_length = int(self.freq_key_length.get())
                position = int(self.freq_position.get())
            except ValueError:
                messagebox.showerror("Input Error", "Key length and position must be positive integers")
                return
            if position > key_length:
                messagebox.showerror("Input Error", "Position cannot be greater than key length")
                return
            # Extract the column of characters at the given position
            column = clean_text[(position-1)::key_length]
            if not column:
                messagebox.showerror("Analysis Error", "Not enough text for the selected position")
                return
            # Calculate letter frequencies
            freq = {}
            for letter in string.ascii_uppercase:
                freq[letter] = column.count(letter) / len(column) if len(column) > 0 else 0
            # Draw frequency chart
            self.draw_frequency_chart(freq)
            # Find most likely key character for this position
            shifts = []
            scores = []
            for shift in range(26):
                # Apply the shift and get expected distribution
                shifted = ''.join(chr(((ord(c)-ord('A')-shift) % 26) + ord('A')) for c in column)
                shift_freq = {}
                for letter in string.ascii_uppercase:
                    shift_freq[letter] = shifted.count(letter) / len(shifted) if len(shifted) > 0 else 0
                # Calculate chi-squared against English frequencies
                score = 0
                for letter, english_freq in ENGLISH_FREQS.items():
                    observed = shift_freq.get(letter, 0)
                    expected = english_freq
                    if expected > 0:
                        score += ((observed - expected) ** 2) / expected
                shifts.append((shift, chr((shift + ord('A')) % 26), score))
                scores.append(score)
            # Sort by score (lower is better)
            shifts.sort(key=lambda x: x[2])
            # Show results
            self.freq_results.delete(0, tk.END)
            top_keys = "".join(shift[1] for shift in shifts[:5])
            self.freq_results.insert(0, top_keys)
            # Show detailed analysis
            self.freq_details.delete(1.0, tk.END)
            self.freq_details.insert(tk.END, f"Analysis for key length {key_length}, position {position}\n\n")
            self.freq_details.insert(tk.END, f"Characters analyzed: {len(column)}\n")
            self.freq_details.insert(tk.END, f"Top 5 key character candidates:\n")
            for i, (shift, letter, score) in enumerate(shifts[:5], 1):
                self.freq_details.insert(tk.END, f"{i}. '{letter}' (shift={shift}, score={score:.2f})\n")
            self.freq_details.insert(tk.END, f"\nLetter frequencies in column:\n")
            sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
            freq_str = ", ".join(f"{letter}:{freq:.3f}" for letter, freq in sorted_freq if freq > 0)
            self.freq_details.insert(tk.END, freq_str)
            self.update_status(f"Frequency analysis completed for position {position}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error occurred during frequency analysis")

    def draw_frequency_chart(self, freq):
        """Draw a bar chart of letter frequencies"""
        self.freq_canvas.delete("all")
        width = self.freq_canvas.winfo_width() or 800
        height = self.freq_canvas.winfo_height() or 300
        # Leave margins
        margin_x = 40
        margin_y = 30
        chart_width = width - 2 * margin_x
        chart_height = height - 2 * margin_y
        # Draw axes
        self.freq_canvas.create_line(margin_x, height - margin_y, 
                                   width - margin_x, height - margin_y, width=2)
        self.freq_canvas.create_line(margin_x, margin_y, 
                                   margin_x, height - margin_y, width=2)
        # Draw labels
        self.freq_canvas.create_text(width // 2, height - 10, 
                                  text="Letters", font=("Helvetica", 10, "bold"))
        self.freq_canvas.create_text(15, height // 2, 
                                  text="Frequency", font=("Helvetica", 10, "bold"), angle=90)
        # Draw English average line
        max_eng_freq = max(ENGLISH_FREQS.values())
        eng_y = height - margin_y - (chart_height * max_eng_freq / 0.13)
        self.freq_canvas.create_line(margin_x, eng_y, width - margin_x, eng_y, 
                                  fill="red", dash=(4, 4))
        self.freq_canvas.create_text(width - margin_x + 5, eng_y, 
                                  text="English Avg", fill="red", anchor=tk.W)
        # Draw bars
        bar_width = chart_width / 26
        max_freq = max(freq.values()) if freq else 0.13
        max_scale = max(max_freq, 0.13)  # Use at least 13% for scale
        for i, letter in enumerate(string.ascii_uppercase):
            frequency = freq.get(letter, 0)
            bar_height = chart_height * frequency / max_scale if max_scale > 0 else 0
            x1 = margin_x + i * bar_width
            y1 = height - margin_y - bar_height
            x2 = x1 + bar_width * 0.8
            y2 = height - margin_y
            # Color bars differently for higher frequencies
            color = "#ff9800" if frequency > ENGLISH_FREQS.get(letter, 0) else "#4caf50"
            self.freq_canvas.create_rectangle(x1, y1, x2, y2, fill=color)
            self.freq_canvas.create_text(x1 + bar_width/2, y2 + 10, text=letter)
            self.freq_canvas.create_text(x1 + bar_width/2, y1 - 5, text=f"{frequency:.3f}" if frequency > 0.01 else "")

    def quick_decrypt_test(self):
        """Perform a quick decryption test with the entered key"""
        try:
            key = self.test_key.get().strip().upper()
            if not key:
                messagebox.showerror("Input Error", "Please enter a test key")
                return
                
            ciphertext = self.kasiski_ciphertext.get(1.0, tk.END).strip()
            clean_text = ''.join(c for c in ciphertext.upper() if c in string.ascii_uppercase)
            
            if not clean_text:
                messagebox.showerror("Input Error", "Please enter ciphertext to decrypt")
                return
                
            # Decrypt the text
            plaintext = decrypt_vigenere(clean_text, key)
            
            # Display results
            self.test_result.delete(1.0, tk.END)
            self.test_result.insert(tk.END, plaintext)
            
            self.update_status(f"Quick test decryption with key '{key}' completed")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error in quick decryption test")

    def copy_to_frequency(self):
        """Copy text from Kasiski tab to Frequency Analysis tab"""
        text = self.kasiski_ciphertext.get(1.0, tk.END)
        self.freq_ciphertext.delete(1.0, tk.END)
        self.freq_ciphertext.insert(tk.END, text)
        self.update_status("Copied text to Frequency Analysis tab")

    def clear_frequency(self):
        """Clear all fields in the Frequency Analysis tab"""
        self.freq_ciphertext.delete(1.0, tk.END)
        self.freq_key_length.current(4)  # Default to 5
        self.freq_position.current(0)
        self.freq_results.delete(0, tk.END)
        self.freq_details.delete(1.0, tk.END)
        self.freq_canvas.delete("all")
        self.update_status("Cleared Frequency Analysis fields")

    def run_kasiski_analysis(self):
        """Run the Kasiski examination to crack a Vigenère cipher"""
        try:
            ciphertext = self.kasiski_ciphertext.get(1.0, tk.END).strip()
            min_seq_len = int(self.kasiski_min_len.get())
            max_key_len = int(self.kasiski_max_len.get())
            language = self.kasiski_lang.get().lower()
            if not ciphertext:
                messagebox.showerror("Input Error", "Please provide the encrypted text")
                return
            if min_seq_len < 2:
                messagebox.showerror("Input Error", "Minimum sequence length must be at least 2")
                return
            if max_key_len < 1:
                messagebox.showerror("Input Error", "Maximum key length must be positive")
                return

            # Clear previous results
            for item in self.key_tree.get_children():
                self.key_tree.delete(item)
            for item in self.decrypt_tree.get_children():
                self.decrypt_tree.delete(item)
            self.analysis_text.delete(1.0, tk.END)

            self.kasiski_status.set("Running Kasiski examination...")
            self.kasiski_progress['value'] = 0
            self.kasiski_run_btn.config(state=tk.DISABLED)
            self.update_status("Running Kasiski examination on Vigenère cipher...")

            def run_analysis():
                start_time = time.time()
                clean_text = ''.join(c for c in ciphertext.upper() if c in string.ascii_uppercase)
                self.root.after(0, lambda: self.update_kasiski_progress(10, "Finding repeated sequences..."))
                result = kasiski_examination(clean_text, min_seq_len, max_key_len)
                elapsed_time = time.time() - start_time
                self.root.after(0, lambda: self.update_kasiski_results(result, clean_text, elapsed_time))

            threading.Thread(target=run_analysis, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.kasiski_status.set("Error occurred")
            self.kasiski_run_btn.config(state=tk.NORMAL)
            self.update_status("Error occurred during Kasiski examination")

    def update_kasiski_progress(self, value=0, status_text=""):
        """Update the progress bar and status text"""
        try:
            progress_value = int(value) if value is not None else 0
            self.kasiski_progress['value'] = progress_value
            if status_text:
                self.kasiski_status.set(status_text)
            self.root.update()
        except (ValueError, TypeError):
            self.kasiski_progress['value'] = 0
            if status_text:
                self.kasiski_status.set(status_text)
            self.root.update()

    def generate_vigenere_example(self):
        """Generate an example Vigenère ciphertext"""
        try:
            plaintext = ("THEVIGENERECIPHERISAMETHODOFENCRYPTINGALPHABETICTEXTBYUSING"
                         "APOLYALPHABETICSUBSTITUTIONTECHNIQUEDEVELOPEDBYGIOVANBELLASO"
                         "ANDATTRIBUTEDTOVIGENERE").upper()
            key = "CRYPTO"
            ciphertext = vigenere_encrypt(plaintext, key)

            # Update input field
            self.kasiski_ciphertext.delete(1.0, tk.END)
            self.kasiski_ciphertext.insert(tk.END, ciphertext)

            # Clear existing results
            for item in self.key_tree.get_children():
                self.key_tree.delete(item)
            for item in self.decrypt_tree.get_children():
                self.decrypt_tree.delete(item)
            self.analysis_text.delete(1.0, tk.END)

            # Show example info in analysis text
            self.analysis_text.insert(tk.END, "Generated Vigenère Example:\n\n")
            self.analysis_text.insert(tk.END, f"Original key: {key}\n")
            self.analysis_text.insert(tk.END, f"Plaintext length: {len(plaintext)} characters\n")
            self.analysis_text.insert(tk.END, f"Ciphertext length: {len(ciphertext)} characters\n\n")
            self.analysis_text.insert(tk.END, "Click 'Run Kasiski Analysis' to try breaking the cipher\n")

            self.update_status("Generated Vigenère cipher example")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status("Error generating example")

    def clear_kasiski(self):
        """Clear all fields in the Kasiski tab"""
        # Clear input fields
        self.kasiski_ciphertext.delete(1.0, tk.END)
        self.kasiski_min_len.delete(0, tk.END)
        self.kasiski_min_len.insert(0, "3")
        self.kasiski_max_len.delete(0, tk.END)
        self.kasiski_max_len.insert(0, "10")

        # Clear results
        for item in self.key_tree.get_children():
            self.key_tree.delete(item)
        for item in self.decrypt_tree.get_children():
            self.decrypt_tree.delete(item)
        self.analysis_text.delete(1.0, tk.END)

        # Reset progress and status
        self.kasiski_progress['value'] = 0
        self.kasiski_status.set("Ready")
        self.update_status("Cleared Kasiski examination fields")

    def decrypt_with_key(self):
        """Decrypt ciphertext using the provided key"""
        try:
            # Get key and ciphertext
            key = self.verify_key.get().strip().upper()
            if not key:
                messagebox.showerror("Input Error", "Please enter a decryption key")
                return
            # Get original ciphertext from Kasiski tab if available
            ciphertext = self.kasiski_ciphertext.get(1.0, tk.END).strip()
            clean_ciphertext = ''.join(c for c in ciphertext.upper() if c in string.ascii_uppercase)
            
            if not clean_ciphertext:
                messagebox.showerror("Input Error", "No ciphertext available to decrypt")
                return
            
            # Check if key contains only valid characters
            if not all(c in string.ascii_uppercase for c in key):
                messagebox.showerror("Input Error", "Key must contain only alphabetic characters")
                return
            
            # Import the decrypt_vigenere function if not imported already
            from attacks.vigenere.kasiski import decrypt_vigenere
            
            # Decrypt the ciphertext
            plaintext = decrypt_vigenere(clean_ciphertext, key)
            
            # Update the verification panes
            self.verify_ciphertext.delete(1.0, tk.END)
            self.verify_ciphertext.insert(tk.END, clean_ciphertext)
            
            self.verify_plaintext.delete(1.0, tk.END)
            self.verify_plaintext.insert(tk.END, plaintext)
            
            # Switch to the Verify/Decrypt tab
            self.results_notebook.select(3)  # Index 3 for the Verify/Decrypt tab
            
            self.update_status(f"Decryption completed with key: {key}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption error: {str(e)}")
            self.update_status("Error occurred during decryption")

    def use_selected_key(self):
        """Use the selected key from the Key Analysis table"""
        try:
            # Get selected item
            selection = self.key_tree.selection()
            if not selection:
                messagebox.showinfo("Selection Required", "Please select a key from the Key Analysis table")
                return
            # Get key from selected item
            item = self.key_tree.item(selection[0])
            key = item['values'][1]  # Key is in the second column
            # Set key in the verification field
            self.verify_key.delete(0, tk.END)
            self.verify_key.insert(0, key)
            
            # Automatically decrypt with this key
            self.decrypt_with_key()
        except Exception as e:
            messagebox.showerror("Error", f"Error using selected key: {str(e)}")
            self.update_status("Error selecting key")
