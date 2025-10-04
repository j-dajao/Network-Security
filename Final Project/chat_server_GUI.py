# === chat_server_GUI.py ===

import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import hashlib

def mono_decrypt(ciphertext):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    table = str.maketrans(key, alphabet)
    return ciphertext.translate(table)

def vigenere_decrypt(ciphertext, key):
    plaintext = ''
    key = key.upper()
    key_len = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            k = ord(key[i % key_len].upper()) - ord('A')
            decrypted = chr((ord(char) - offset - k) % 26 + offset)
            plaintext += decrypted
        else:
            plaintext += char
    return plaintext

def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def undo_swap(s):
    s = list(s)
    for i in range(0, len(s) - 1, 2):
        s[i], s[i + 1] = s[i + 1], s[i]
    return ''.join(s)

def reverse_transposition(s):
    chars = list(s)
    result = []
    for i in range(0, len(chars), 4):
        block = chars[i:i+4]
        result.extend(block[::-1])
    return ''.join(result)

def decrypt_full_message(rsa_decrypted_bytes, vernam_key):
    steps = {}

    after_xor = xor_decrypt(rsa_decrypted_bytes, vernam_key)
    try:
        text_xor = after_xor.decode()
    except UnicodeDecodeError:
        text_xor = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in after_xor)
    steps["🧪 After XOR (Vernam)"] = text_xor

    text_swapped = undo_swap(text_xor)
    steps["🔄 After Undo Swap"] = text_swapped

    text_transposed = reverse_transposition(text_swapped)
    steps["🔁 After Reverse Transposition"] = text_transposed

    vigenere_key = "KEY"
    text_vigenere = vigenere_decrypt(text_transposed, vigenere_key)
    steps["🔐 After Vigenère Decryption"] = text_vigenere

    final_plaintext = mono_decrypt(text_vigenere)
    steps["✅ Final Plaintext"] = final_plaintext

    return final_plaintext, steps


with open("server_private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
cipher_rsa = PKCS1_OAEP.new(private_key)


class ChatServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Server")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=30)
        self.text_area.pack(padx=10, pady=10)
        self.text_area.config(state='disabled')

        self.entry = tk.Entry(root, width=60)
        self.entry.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 10))

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5, pady=(0, 10))

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 12345))
        self.server_socket.listen(1)

        self.display("✅ Server listening on port 12345...")

        threading.Thread(target=self.accept_connection, daemon=True).start()

    def display(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state='disabled')
        self.text_area.yview(tk.END)

    def accept_connection(self):
        self.client_socket, addr = self.server_socket.accept()
        self.display(f"📶 Connection from {addr}")
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                encrypted_data = self.client_socket.recv(4096)
                vernam_key_b64 = self.client_socket.recv(4096).decode()
                hash_value = self.client_socket.recv(1024).decode()

                vernam_key = base64.b64decode(vernam_key_b64)
                rsa_decrypted = cipher_rsa.decrypt(encrypted_data)
                calculated_hash = hashlib.sha256(rsa_decrypted).hexdigest()

                plaintext, steps = decrypt_full_message(rsa_decrypted, vernam_key)

                self.display("\n🔐 === Encrypted Message Received ===")
                self.display(f"• Ciphertext (base64): {base64.b64encode(encrypted_data).decode()}")
                self.display(f"• Vernam Key (base64): {vernam_key_b64}")
                self.display(f"• Received Hash: {hash_value}")
                self.display(f"• Calculated Hash: {calculated_hash}")

                if calculated_hash != hash_value:
                    self.display("⚠️  Hash mismatch! Message may be tampered.")
                else:
                    self.display("✅ Hash verified.")

                self.display("\n🧩 Decryption Steps:")
                for step, value in steps.items():
                    self.display(f"{step}: {value}")

                self.display(f"\n📥 Final message from client: {plaintext}")

            except Exception as e:
                self.display(f"❌ Error: {str(e)}")
                break

    def send_message(self):
        message = self.entry.get()
        if message:
            try:
                self.client_socket.send(message.encode())
                self.display(f"📤 Server: {message}")
                self.entry.delete(0, tk.END)
            except Exception as e:
                self.display(f"❌ Error sending message: {str(e)}")

if __name__ == '__main__':
    root = tk.Tk()
    app = ChatServer(root)
    root.mainloop()
