#!/usr/bin/env python3
import unittest
from src.ciphers import *

class TestCiphers(unittest.TestCase):
    """Unit tests for cipher functions."""

    def test_caesar(self):
        """Test Caesar cipher encryption and decryption."""
        text = "Hello, World!"
        shift = 3
        encrypted = caesar_encrypt(text, shift)
        self.assertEqual(caesar_decrypt(encrypted, shift), text)

    def test_xor(self):
        """Test XOR cipher encryption and decryption."""
        text = "Hello, World!"
        key = b"key"
        encrypted = xor_encrypt_decrypt(text, key)
        decrypted = xor_encrypt_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    def test_vigenere(self):
        """Test Vigenère cipher encryption and decryption."""
        text = "Hello, World!"
        key = "key"
        encrypted = vigenere_encrypt(text, key)
        self.assertEqual(vigenere_decrypt(encrypted, key), text)

    def test_aes(self):
        """Test AES encryption and decryption."""
        text = "Hello, World!"
        key = generate_random_aes_key()
        encrypted = aes_encrypt(text, key)
        decrypted = aes_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

if __name__ == '__main__':
    unittest.main()
