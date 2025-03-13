"""
Base UI Component class for attack tabs
"""
import tkinter as tk
from tkinter import ttk, scrolledtext

class UIComponent:
    """Base class for UI components"""
    def __init__(self, parent, app):
        """
        Initialize the UI component
        
        Args:
            parent: Parent frame
            app: Main application instance (CryptoAttackTool)
        """
        self.parent = parent
        self.app = app
        self.root = app.root  # Tk root window
        self.frame = tk.Frame(parent, padx=10, pady=10)
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Bind custom status update event
        self.root.bind("<<StatusUpdate>>", self._on_status_update)
    
    def setup_ui(self):
        """Setup UI components - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement setup_ui()")
    
    def create_labeled_entry(self, parent, label_text, row=0, column=0, entry_width=50):
        """Create a labeled entry field"""
        tk.Label(parent, text=label_text).grid(row=row, column=column, sticky=tk.W)
        entry = tk.Entry(parent, width=entry_width)
        entry.grid(row=row, column=column+1, padx=5, pady=5)
        return entry
    
    def create_scrolled_text(self, parent, height=5, width=50):
        """Create a scrolled text widget"""
        text_widget = scrolledtext.ScrolledText(parent, height=height, width=width)
        return text_widget
    
    def create_button(self, parent, text, command, bg='#3a7ebf', fg='white'):
        """Create a styled button"""
        button = tk.Button(parent, text=text, command=command, bg=bg, fg=fg, padx=10)
        return button
    
    def update_status(self, text):
        """Update the status bar with text"""
        if hasattr(self.app, 'update_status'):
            self.app.update_status(text)
        else:
            try:
                self.root.event_generate("<<StatusUpdate>>", data=text)
            except tk.TclError:
                if hasattr(self.app, 'status_var'):
                    self.app.status_var.set(text)
    
    def _on_status_update(self, event):
        """Handle status update events"""
        if hasattr(self.app, 'status_var'):
            self.app.status_var.set(getattr(event, 'data', "Status updated"))
    
    def generate_event(self, event_name, data=None):
        """Generate a custom event"""
        self.root.event_generate(event_name, data=data)
