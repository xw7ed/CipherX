#!/usr/bin/env python3
import random
import tkinter as tk
from tkinter import filedialog, messagebox
from itertools import cycle
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Caesar Cipher
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# XOR Cipher (Improved with longer key)
def xor_encrypt_decrypt(text, key):
    key = key.encode('utf-8') if isinstance(key, str) else key
    key_cycle = cycle(key)
    result = ''.join(chr(ord(char) ^ next(key_cycle)) for char in text)
    return result

# Vigenère Cipher
def vigenere_encrypt(text, key):
    result = []
    key_cycle = cycle(key)
    for char, k in zip(text, key_cycle):
        if char.isalpha():
            shift = ord(k.lower()) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(text, key):
    result = []
    key_cycle = cycle(key)
    for char, k in zip(text, key_cycle):
        if char.isalpha():
            shift = ord(k.lower()) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)

# AES Encryption/Decryption
def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def aes_decrypt(enc_text, key):
    iv = b64decode(enc_text[:24])
    ct = b64decode(enc_text[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt

# Key Generation
def generate_random_xor_key(length):
    return os.urandom(length)

def generate_random_aes_key():
    return os.urandom(16)  # 128-bit key for AES

# File Read/Write
def read_file():
    try:
        file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as file:
                return file.read()
        return ""
    except Exception as e:
        messagebox.showerror("File Error", f"Failed to read file: {str(e)}")
        return ""

def save_file(text):
    try:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(text)
    except Exception as e:
        messagebox.showerror("File Error", f"Failed to save file: {str(e)}")

# Cipher Functions (Refactored)
def perform_caesar(text, choice, shift):
    try:
        shift = int(shift)
        return caesar_encrypt(text, shift) if choice == 'e' else caesar_decrypt(text, shift)
    except ValueError:
        messagebox.showwarning("Input Error", "Please enter a valid shift value.")
        return None

def perform_xor(text, choice, key, text_length):
    try:
        if key == "Random":
            key = generate_random_xor_key(text_length)
            var_key.set(b64encode(key).decode('utf-8'))  # Show the key to the user
        else:
            key = key.encode('utf-8')
        return xor_encrypt_decrypt(text, key)
    except Exception as e:
        messagebox.showwarning("Input Error", f"Invalid key for XOR: {str(e)}")
        return None

def perform_vigenere(text, choice, key):
    if not key.isalpha():
        messagebox.showwarning("Input Error", "Vigenère key must contain only letters.")
        return None
    return vigenere_encrypt(text, key) if choice == 'e' else vigenere_decrypt(text, key)

def perform_aes(text, choice, key):
    try:
        if key == "Random":
            key = generate_random_aes_key()
            var_key.set(b64encode(key).decode('utf-8'))  # Show the key to the user
        else:
            if len(key) != 16:
                messagebox.showwarning("Input Error", "AES key must be 16 characters long.")
                return None
            key = key.encode('utf-8')
        
        if choice == 'e':
            return aes_encrypt(text, key)
        else:
            if len(text) < 24:  # IV must be 24 characters after base64 encoding
                messagebox.showwarning("Input Error", "Invalid AES encrypted text format.")
                return None
            return aes_decrypt(text, key)
    except Exception as e:
        messagebox.showwarning("Input Error", f"Error in AES operation: {str(e)}")
        return None

# Main Encrypt/Decrypt Function
def on_encrypt_decrypt():
    choice = var_choice.get().lower()
    cipher_type = var_cipher_type.get().lower()
    text = var_text.get("1.0", tk.END).strip()

    if not text:
        messagebox.showwarning("Input Error", "Please enter or select a text.")
        return

    result = None
    if cipher_type == 'caesar':
        result = perform_caesar(text, choice, var_shift.get())
    elif cipher_type == 'xor':
        result = perform_xor(text, choice, var_key.get(), len(text))
    elif cipher_type == 'vigenere':
        result = perform_vigenere(text, choice, var_key.get())
    elif cipher_type == 'aes':
        result = perform_aes(text, choice, var_key.get())

    if result is not None:
        var_result.delete("1.0", tk.END)
        var_result.insert(tk.END, result)

# GUI Helper Functions
def on_file_open():
    text = read_file()
    if text:
        var_text.delete("1.0", tk.END)
        var_text.insert(tk.END, text)

def on_save_file():
    text = var_result.get("1.0", tk.END).strip()
    if text:
        save_file(text)
    else:
        messagebox.showwarning("Save Error", "Nothing to save!")

def copy_result():
    root.clipboard_clear()
    root.clipboard_append(var_result.get("1.0", tk.END).strip())
    messagebox.showinfo("Success", "Result copied to clipboard!")

def clear_fields():
    var_text.delete("1.0", tk.END)
    var_result.delete("1.0", tk.END)
    var_shift.set("3")
    var_key.set("Random")

# Dynamic UI Update
def update_ui(*args):
    cipher_type = var_cipher_type.get().lower()
    for widget in frame_input.grid_slaves():
        if widget.grid_info()['row'] in [2, 3]:  # Hide Shift and Key fields
            widget.grid_forget()
    
    if cipher_type == 'caesar':
        tk.Label(frame_input, text="Enter Shift Value:").grid(row=2, column=0, sticky="w")
        tk.Entry(frame_input, textvariable=var_shift, width=10).grid(row=2, column=1)
    elif cipher_type in ['xor', 'vigenere', 'aes']:
        tk.Label(frame_input, text="Enter Key (or 'Random' for XOR/AES):").grid(row=2, column=0, sticky="w")
        tk.Entry(frame_input, textvariable=var_key, width=10).grid(row=2, column=1)

# GUI Setup
root = tk.Tk()
root.title("Encryption and Decryption Tool - User: w7ed")

# Input Section
frame_input = tk.Frame(root)
frame_input.pack(padx=10, pady=10)

tk.Label(frame_input, text="Choose Operation:").grid(row=0, column=0, sticky="w")
var_choice = tk.StringVar(value='e')
tk.Radiobutton(frame_input, text="Encrypt", variable=var_choice, value='e').grid(row=0, column=1)
tk.Radiobutton(frame_input, text="Decrypt", variable=var_choice, value='d').grid(row=0, column=2)

tk.Label(frame_input, text="Select Cipher:").grid(row=1, column=0, sticky="w")
var_cipher_type = tk.StringVar(value='caesar')
cipher_options = ['caesar', 'xor', 'vigenere', 'aes']
tk.OptionMenu(frame_input, var_cipher_type, *cipher_options).grid(row=1, column=1)
var_cipher_type.trace('w', update_ui)

var_shift = tk.StringVar(value="3")
var_key = tk.StringVar(value="Random")
update_ui()  # Initial UI setup

tk.Label(frame_input, text="Enter Text:").grid(row=4, column=0, sticky="w")
var_text = tk.Text(frame_input, height=5, width=40)
var_text.grid(row=4, column=1, pady=10)

tk.Button(frame_input, text="Open File", command=on_file_open).grid(row=5, column=0, pady=5)
tk.Button(frame_input, text="Save Result", command=on_save_file).grid(row=5, column=1, pady=5)
tk.Button(frame_input, text="Clear All", command=clear_fields).grid(row=5, column=2, pady=5)

# Output Section
frame_output = tk.Frame(root)
frame_output.pack(padx=10, pady=10)

tk.Label(frame_output, text="Result:").grid(row=0, column=0, sticky="w")
var_result = tk.Text(frame_output, height=5, width=40)
var_result.grid(row=0, column=1)

tk.Button(frame_output, text="Encrypt/Decrypt", command=on_encrypt_decrypt).grid(row=1, column=0, columnspan=2, pady=10)
tk.Button(frame_output, text="Copy Result", command=copy_result).grid(row=2, column=0, columnspan=2, pady=5)

root.mainloop()
