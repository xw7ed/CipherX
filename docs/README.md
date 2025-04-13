CryptoTool
CryptoTool is a Python-based encryption and decryption application built with Tkinter. It supports multiple ciphers including Caesar, XOR, Vigenère, and AES, with a user-friendly GUI for encrypting/decrypting text and files.

Features
Supports Caesar, XOR, Vigenère, and AES ciphers.
Encrypt/decrypt text or files.
Generate random keys for XOR and AES.
Copy results to clipboard or save to files.
Clean and modern UI with dynamic input fields.
Prerequisites
Python 3.8+
Required libraries: pycryptodome, tkinter (included with Python)
Installation
Clone the repository:
bash



git clone https://github.com/thesaud/cryptotool.git
cd cryptotool
Install dependencies:
bash



pip install -r requirements.txt
Run the application:
bash



python src/main.py
Usage
Select Encrypt or Decrypt.
Choose a cipher (Caesar, XOR, Vigenère, or AES).
Enter the text or open a file.
Provide a shift value (for Caesar) or key (for others; use "Random" for XOR/AES to generate a key).
Click Encrypt/Decrypt to process.
Copy the result or save it to a file.
Project Structure
text



cryptotool/
├── src/
│   ├── ciphers.py        # Cipher functions
│   ├── gui.py           # GUI implementation
│   ├── file_manager.py  # File handling
│   └── main.py          # Entry point
├── tests/
│   └── test_ciphers.py  # Unit tests
├── docs/
│   └── README.md        # Documentation
├── requirements.txt      # Dependencies
└── .gitignore           # Git ignore file
Testing
Run unit tests to verify cipher functionality:

bash



python -m unittest discover tests
Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

License
This project is licensed under the MIT License.
