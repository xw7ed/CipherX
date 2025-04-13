
#dDeveloped by : M3
#!/usr/bin/env python3
import random
import tkinter as tk
from tkinter import filedialog, messagebox
from itertools import cycle
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

# XOR Cipher
def xor_encrypt_decrypt(text, key):
    result = ""
    for char in text:
        result += chr(ord(char) ^ key)
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
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def aes_decrypt(enc_text, key):
    iv = b64decode(enc_text[:24])
    ct = b64decode(enc_text[24:])
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt

# Random Key Generation for XOR
def generate_random_key():
    return random.randint(0, 255)

# File Read/Write
def read_file():
    file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    return ""

def save_file(text):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(text)

# Main Encrypt/Decrypt Function
def on_encrypt_decrypt():
    choice = var_choice.get().lower()
    cipher_type = var_cipher_type.get().lower()
    text = var_text.get("1.0", tk.END).strip()

    if not text:
        messagebox.showwarning("Input Error", "Please enter or select a text.")
        return

    if cipher_type == 'caesar':
        try:
            shift = int(var_shift.get())
            if choice == 'e':
                result = caesar_encrypt(text, shift)
            elif choice == 'd':
                result = caesar_decrypt(text, shift)
            else:
                messagebox.showwarning("Input Error", "Invalid choice for encryption/decryption.")
                return
        except ValueError:
            messagebox.showwarning("Input Error", "Please enter a valid shift value.")
            return
    
    elif cipher_type == 'xor':
        try:
            if var_key.get() == "Random":
                key = generate_random_key()
                var_key_value.set(str(key))
            else:
                key = int(var_key.get())
            if choice == 'e' or choice == 'd':
                result = xor_encrypt_decrypt(text, key)
            else:
                messagebox.showwarning("Input Error", "Invalid choice for encryption/decryption.")
                return
        except ValueError:
            messagebox.showwarning("Input Error", "Please enter a valid key for XOR.")
            return

    elif cipher_type == 'vigenere':
        try:
            key = var_key.get()
            if choice == 'e':
                result = vigenere_encrypt(text, key)
            elif choice == 'd':
                result = vigenere_decrypt(text, key)
            else:
                messagebox.showwarning("Input Error", "Invalid choice for encryption/decryption.")
                return
        except ValueError:
            messagebox.showwarning("Input Error", "Please enter a valid key for Vigenère.")
            return

    elif cipher_type == 'aes':
        try:
            key = var_key.get()
            if len(key) != 16:
                messagebox.showwarning("Input Error", "AES key must be 16 characters long.")
                return
            if choice == 'e':
                result = aes_encrypt(text, key)
            elif choice == 'd':
                result = aes_decrypt(text, key)
            else:
                messagebox.showwarning("Input Error", "Invalid choice for encryption/decryption.")
                return
        except ValueError:
            messagebox.showwarning("Input Error", "Please enter a valid key for AES.")
            return

    else:
        messagebox.showwarning("Input Error", "Invalid cipher type selected.")
        return
    
    var_result.delete("1.0", tk.END)
    var_result.insert(tk.END, result)

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

# GUI Setup
root = tk.Tk()
root.title("Encryption and Decryption Tool - User: w7ed")

# Input Section
frame_input = tk.Frame(root)
frame_input.pack(padx=10, pady=10)

tk.Label(frame_input, text="Choose (e) to Encrypt or (d) to Decrypt:").grid(row=0, column=0, sticky="w")
var_choice = tk.StringVar(value='e')
tk.Entry(frame_input, textvariable=var_choice, width=10).grid(row=0, column=1)

tk.Label(frame_input, text="Select Cipher (caesar/xor/vigenere/aes):").grid(row=1, column=0, sticky="w")
var_cipher_type = tk.StringVar(value='caesar')
tk.Entry(frame_input, textvariable=var_cipher_type, width=10).grid(row=1, column=1)

tk.Label(frame_input, text="Enter Shift Value (for Caesar) or Key (for XOR, Vigenère, AES):").grid(row=2, column=0, sticky="w")
var_shift = tk.StringVar(value="3")
tk.Entry(frame_input, textvariable=var_shift, width=10).grid(row=2, column=1)

tk.Label(frame_input, text="Enter XOR/Vigenère/AES Key or Select Random:").grid(row=3, column=0, sticky="w")
var_key = tk.StringVar(value="Random")
tk.Entry(frame_input, textvariable=var_key, width=10).grid(row=3, column=1)

tk.Label(frame_input, text="Enter Text:").grid(row=4, column=0, sticky="w")
var_text = tk.Text(frame_input, height=5, width=40)
var_text.grid(row=4, column=1, pady=10)

tk.Button(frame_input, text="Open File", command=on_file_open).grid(row=5, column=0, pady=5)
tk.Button(frame_input, text="Save Result", command=on_save_file).grid(row=5, column=1, pady=5)

# Output Section
frame_output = tk.Frame(root)
frame_output.pack(padx=10, pady=10)

tk.Label(frame_output, text="Result:").grid(row=0, column=0, sticky="w")
var_result = tk.Text(frame_output, height=5, width=40)
var_result.grid(row=0, column=1)

tk.Button(frame_output, text="Encrypt/Decrypt", command=on_encrypt_decrypt).grid(row=1, column=0, columnspan=2, pady=10)

root.mainloop()
