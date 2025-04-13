#!/usr/bin/env python3
import os
from itertools import cycle
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypts text using Caesar Cipher with the specified shift.

    Args:
        text: The input text to encrypt.
        shift: The number of positions to shift each letter.

    Returns:
        The encrypted text.
    """
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypts text encrypted with Caesar Cipher.

    Args:
        text: The encrypted text.
        shift: The shift used for encryption.

    Returns:
        The decrypted text.
    """
    return caesar_encrypt(text, -shift)

def xor_encrypt_decrypt(text: str, key: bytes) -> str:
    """Encrypts or decrypts text using XOR with a key.

    Args:
        text: The input text.
        key: The key for XOR operation.

    Returns:
        The encrypted/decrypted text.
    """
    key_cycle = cycle(key)
    return ''.join(chr(ord(char) ^ next(key_cycle)) for char in text)

def vigenere_encrypt(text: str, key: str) -> str:
    """Encrypts text using Vigenère Cipher.

    Args:
        text: The input text.
        key: The key for encryption.

    Returns:
        The encrypted text.
    """
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

def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypts text encrypted with Vigenère Cipher.

    Args:
        text: The encrypted text.
        key: The key used for encryption.

    Returns:
        The decrypted text.
    """
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

def aes_encrypt(text: str, key: bytes) -> str:
    """Encrypts text using AES (CBC mode).

    Args:
        text: The input text.
        key: The 16-byte key for AES.

    Returns:
        The encrypted text (IV + ciphertext, base64 encoded).
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def aes_decrypt(enc_text: str, key: bytes) -> str:
    """Decrypts text encrypted with AES (CBC mode).

    Args:
        enc_text: The encrypted text (IV + ciphertext).
        key: The 16-byte key used for encryption.

    Returns:
        The decrypted text.
    """
    iv = b64decode(enc_text[:24])
    ct = b64decode(enc_text[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

def generate_random_xor_key(length: int) -> bytes:
    """Generates a random key for XOR cipher.

    Args:
        length: The length of the key in bytes.

    Returns:
        A random byte string.
    """
    return os.urandom(length)

def generate_random_aes_key() -> bytes:
    """Generates a random 16-byte key for AES.

    Returns:
        A random 16-byte key.
    """
    return os.urandom(16)