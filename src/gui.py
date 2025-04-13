#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox
from .ciphers import *
from .file_manager import read_file, save_file
from base64 import b64encode, b64decode

class EncryptionApp:
    """Main GUI application for encryption and decryption."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CryptoTool")
        self.root.geometry("600x500")
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass
        
        # Variables
        self.var_choice = tk.StringVar(value='e')
        self.var_cipher_type = tk.StringVar(value='caesar')
        self.var_shift = tk.StringVar(value="3")
        self.var_key = tk.StringVar(value="Random")
        
        # Styles
        self.root.configure(bg="#f0f0f0")
        self.label_style = {"bg": "#f0f0f0", "font": ("Arial", 12)}
        self.button_style = {"bg": "#4CAF50", "fg": "white", "font": ("Arial", 10), "width": 15}
        
        self.setup_ui()
        self.var_cipher_type.trace('w', self.update_ui)

    def setup_ui(self):
        """Sets up the main GUI layout."""
        # Input Frame
        self.frame_input = tk.Frame(self.root, bg="#f0f0f0")
        self.frame_input.pack(padx=10, pady=10, fill="x")

        tk.Label(self.frame_input, text="Operation:", **self.label_style).grid(row=0, column=0, sticky="w")
        tk.Radiobutton(self.frame_input, text="Encrypt", variable=self.var_choice, value='e', bg="#f0f0f0").grid(row=0, column=1)
        tk.Radiobutton(self.frame_input, text="Decrypt", variable=self.var_choice, value='d', bg="#f0f0f0").grid(row=0, column=2)

        tk.Label(self.frame_input, text="Cipher Type:", **self.label_style).grid(row=1, column=0, sticky="w")
        cipher_options = ['caesar', 'xor', 'vigenere', 'aes']
        tk.OptionMenu(self.frame_input, self.var_cipher_type, *cipher_options).grid(row=1, column=1, sticky="w")

        self.input_widgets = {}
        self.update_ui()

        tk.Label(self.frame_input, text="Input Text:", **self.label_style).grid(row=4, column=0, sticky="w")
        self.var_text = tk.Text(self.frame_input, height=5, width=50)
        self.var_text.grid(row=4, column=1, columnspan=2, pady=10)

        tk.Button(self.frame_input, text="Open File", command=self.on_file_open, **self.button_style).grid(row=5, column=0, pady=5)
        tk.Button(self.frame_input, text="Clear All", command=self.clear_fields, **self.button_style).grid(row=5, column=1, pady=5)

        # Output Frame
        self.frame_output = tk.Frame(self.root, bg="#f0f0f0")
        self.frame_output.pack(padx=10, pady=10, fill="x")

        tk.Label(self.frame_output, text="Result:", **self.label_style).grid(row=0, column=0, sticky="w")
        self.var_result = tk.Text(self.frame_output, height=5, width=50)
        self.var_result.grid(row=0, column=1, columnspan=2, pady=10)

        tk.Button(self.frame_output, text="Encrypt/Decrypt", command=self.on_encrypt_decrypt, **self.button_style).grid(row=1, column=0, columnspan=2, pady=10)
        tk.Button(self.frame_output, text="Copy Result", command=self.copy_result, **self.button_style).grid(row=2, column=0, pady=5)
        tk.Button(self.frame_output, text="Save Result", command=self.on_save_file, **self.button_style).grid(row=2, column=1, pady=5)

    def update_ui(self, *args):
        """Dynamically updates input fields based on cipher type."""
        for widget in self.frame_input.grid_slaves():
            if widget.grid_info()['row'] in [2, 3]:
                widget.grid_forget()
        
        cipher_type = self.var_cipher_type.get().lower()
        if cipher_type == 'caesar':
            tk.Label(self.frame_input, text="Shift Value:", **self.label_style).grid(row=2, column=0, sticky="w")
            tk.Entry(self.frame_input, textvariable=self.var_shift, width=10).grid(row=2, column=1, sticky="w")
        elif cipher_type in ['xor', 'vigenere', 'aes']:
            tk.Label(self.frame_input, text="Key:", **self.label_style).grid(row=2, column=0, sticky="w")
            tk.Entry(self.frame_input, textvariable=self.var_key, width=20).grid(row=2, column=1, sticky="w")

    def on_encrypt_decrypt(self):
        """Handles encryption/decryption based on user input."""
        choice = self.var_choice.get().lower()
        cipher_type = self.var_cipher_type.get().lower()
        text = self.var_text.get("1.0", tk.END).strip()

        if not text:
            messagebox.showwarning("Input Error", "Please enter or select a text.")
            return

        result = None
        if cipher_type == 'caesar':
            try:
                shift = int(self.var_shift.get())
                result = caesar_encrypt(text, shift) if choice == 'e' else caesar_decrypt(text, shift)
            except ValueError:
                messagebox.showwarning("Input Error", "Please enter a valid shift value.")
        elif cipher_type == 'xor':
            key = self.var_key.get()
            text_length = len(text)
            if key == "Random":
                key = generate_random_xor_key(text_length)
                self.var_key.set(b64encode(key).decode('utf-8'))
            else:
                key = key.encode('utf-8')
            result = xor_encrypt_decrypt(text, key)
        elif cipher_type == 'vigenere':
            key = self.var_key.get()
            if not key.isalpha():
                messagebox.showwarning("Input Error", "Vigenère key must contain only letters.")
                return
            result = vigenere_encrypt(text, key) if choice == 'e' else vigenere_decrypt(text, key)
        elif cipher_type == 'aes':
            key = self.var_key.get()
            if key == "Random":
                key = generate_random_aes_key()
                self.var_key.set(b64encode(key).decode('utf-8'))
            else:
                if len(key) != 16:
                    messagebox.showwarning("Input Error", "AES key must be 16 characters long.")
                    return
                key = key.encode('utf-8')
            try:
                result = aes_encrypt(text, key) if choice == 'e' else aes_decrypt(text, key)
            except Exception as e:
                messagebox.showwarning("Input Error", f"Error in AES operation: {str(e)}")
                return

        if result is not None:
            self.var_result.delete("1.0", tk.END)
            self.var_result.insert(tk.END, result)

    def on_file_open(self):
        """Opens a file and loads its content into the input text area."""
        text = read_file()
        if text:
            self.var_text.delete("1.0", tk.END)
            self.var_text.insert(tk.END, text)

    def on_save_file(self):
        """Saves the result text to a file."""
        text = self.var_result.get("1.0", tk.END).strip()
        if text:
            save_file(text)
        else:
            messagebox.showwarning("Save Error", "Nothing to save!")

    def copy_result(self):
        """Copies the result text to the clipboard."""
        text = self.var_result.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Success", "Result copied to clipboard!")
        else:
            messagebox.showwarning("Copy Error", "Nothing to copy!")

    def clear_fields(self):
        """Clears all input and output fields."""
        self.var_text.delete("1.0", tk.END)
        self.var_result.delete("1.0", tk.END)
        self.var_shift.set("3")
        self.var_key.set("Random")
