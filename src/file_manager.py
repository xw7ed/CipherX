#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox

def read_file() -> str:
    """Reads content from a text file selected by the user.

    Returns:
        The content of the file, or empty string if failed.
    """
    try:
        file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as file:
                return file.read()
        return ""
    except Exception as e:
        messagebox.showerror("File Error", f"Failed to read file: {str(e)}")
        return ""

def save_file(text: str) -> None:
    """Saves text to a file selected by the user.

    Args:
        text: The text to save.
    """
    try:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(text)
    except Exception as e:
        messagebox.showerror("File Error", f"Failed to save file: {str(e)}")
