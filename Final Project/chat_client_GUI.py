# === chat_client_GUI.py ===

import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import hashlib
import os

def mono_encrypt(plaintext):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    table = str.maketrans(alphabet, key)
    return plaintext.upper().translate(table)

def vigenere_encrypt(plaintext, key):
    ciphertext = ''
    key = key.upper()
    key_len = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            k = ord(key[i % key_len]) - ord('A')
            encrypted = chr((ord(char) - offset + k) % 26 + offset)
            ciphertext += encrypted
        else:
            ciphertext += char
    return ciphertext

def swap_chars(s):
    s = list(s)
    for i in range(0, len(s) - 1, 2):
        s[i], s[i + 1] = s[i + 1], s[i]
    return ''.join(s)

def transposition(s):
    chars = list(s)
    result = []
    for i in range(0, len(chars), 4):
        block = chars[i:i+4]
        result.extend(block[::-1])
    return ''.join(result)

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_full_message(message, rsa_public_key):
    steps = {}

    text_mono = mono_encrypt(message)
    steps["Monoalphabetic Encrypted"] = text_mono

    text_vigenere = vigenere_encrypt(text_mono, "KEY")
    steps["Vigenère Encrypted"] = text_vigenere

    text_swapped = swap_chars(text_vigenere)
    steps["Swapped Characters"] = text_swapped

    text_transposed = transposition(text_swapped)
    steps["Transposition Applied"] = text_transposed

    vernam_key = os.urandom(len(text_transposed))
    xor_encrypted = xor_encrypt(text_transposed.encode(), vernam_key)
    steps["XOR (Vernam) Encrypted"] = base64.b64encode(xor_encrypted).decode()

    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    rsa_encrypted = cipher_rsa.encrypt(xor_encrypted)

    hash_value = hashlib.sha256(xor_encrypted).hexdigest()

    return rsa_encrypted, base64.b64encode(vernam_key).decode(), hash_value, steps

with open("server_public.pem", "rb") as f:
    server_public_key = RSA.import_key(f.read())

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=30)
        self.text_area.pack(padx=10, pady=10)
        self.text_area.config(state='disabled')

        self.entry = tk.Entry(root, width=60)
        self.entry.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 10))

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5, pady=(0, 10))

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #ip change ni
        self.client_socket.connect(('localhost', 12345))

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def display(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state='disabled')
        self.text_area.yview(tk.END)

    def send_message(self):
        message = self.entry.get()
        if message:
            try:
                rsa_encrypted, vernam_key_b64, hash_value, steps = encrypt_full_message(message, server_public_key)

                self.client_socket.send(rsa_encrypted)
                self.client_socket.send(vernam_key_b64.encode())
                self.client_socket.send(hash_value.encode())

                self.display(f"You: {message}")
                self.display("\n=== Encryption Steps ===")
                for k, v in steps.items():
                    self.display(f"  • {k}: {v}")

                self.entry.delete(0, tk.END)
            except Exception as e:
                self.display(f"Error: {str(e)}")

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if data:
                    message = data.decode()
                    self.display(f"Server: {message}")
            except Exception as e:
                self.display(f"Receive error: {e}")
                break

if __name__ == '__main__':
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
