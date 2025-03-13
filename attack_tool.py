#!/usr/bin/env python3
"""
Cryptographic Attack Tool Entry Point

This tool provides a GUI for demonstrating cryptographic attacks including:
- AES-CBC Padding Oracle Attack
- RSA Attacks (Wiener's Attack, Franklin-Reiter Related Message Attack, Pollard Rho)
- Vigenère Cipher Attacks (Kasiski Examination)

For educational and research purposes only.
"""

import tkinter as tk
import sys
import os
import logging
from pathlib import Path

def setup_logging():
    """Configure logging for the application"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def check_dependencies():
    """Check if required packages are installed"""
    missing_packages = []
    
    # Check for pycryptodome (imported as Crypto)
    try:
        import Crypto
    except ImportError:
        missing_packages.append("pycryptodome")
    
    # Check for sympy
    try:
        import sympy
    except ImportError:
        missing_packages.append("sympy")
    
    if missing_packages:
        logging.error(f"Missing dependencies: {', '.join(missing_packages)}")
        print("Please install the following required packages:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nRun: pip install -r requirements.txt")
        return False
    
    return True

def main():
    """Main entry point for the Cryptographic Attack Tool"""
    setup_logging()

    # Add project root to Python path
    project_root = Path(__file__).parent
    sys.path.append(str(project_root))

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    try:
        from app.main_app import CryptoAttackTool
        root = tk.Tk()
        app = CryptoAttackTool(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"Application error: {e}")
        raise

if __name__ == "__main__":
    main()
