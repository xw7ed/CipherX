#!/usr/bin/env python3
import tkinter as tk
from src.gui import EncryptionApp

def main():
    """Entry point for the encryption tool application."""
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
