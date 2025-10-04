import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import hashlib
import struct

# === Decryption Utilities ===

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

    # Step 1: XOR Decryption
    after_xor = xor_decrypt(rsa_decrypted_bytes, vernam_key)
    try:
        text_xor = after_xor.decode()
    except UnicodeDecodeError:
        text_xor = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in after_xor)
    steps["After XOR (Vernam)"] = text_xor

    # Step 2: Reverse Transposition
    text_transposed = reverse_transposition(text_xor)
    steps["After Reverse Transposition"] = text_transposed

    # Step 3: Undo Swap
    text_swapped = undo_swap(text_transposed)
    steps["After Undo Swap"] = text_swapped

    # Step 4: Vigenère Decryption
    vigenere_key = "KEY"
    text_vigenere = vigenere_decrypt(text_swapped, vigenere_key)
    steps["After Vigenère Decryption"] = text_vigenere

    # Step 5: Monoalphabetic Decryption (IMPORTANT - Add to steps to avoid KeyError)
    final_plaintext = mono_decrypt(text_vigenere)
    steps["After undoing Monoalphabetic"] = final_plaintext

    return final_plaintext, steps


def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def receive_full_packet(sock):
    raw_len = recv_all(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    return recv_all(sock, msg_len)

# === Load RSA Private Key ===
with open("server_private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
cipher_rsa = PKCS1_OAEP.new(private_key)

# === GUI Server ===
class ChatServer:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat Server")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=30)
        self.text_area.pack(padx=10, pady=10)
        self.text_area.config(state='disabled')

        self.entry = tk.Entry(root, width=60)
        self.entry.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 10))

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5, pady=(0, 10))

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('10.16.227.152', 25565))  # Change 'localhost' to your server IP for LAN
        self.server_socket.listen(1)

        self.display("✅ Server listening on port 25565...")

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
            packet = receive_full_packet(self.client_socket)
            if not packet:
                self.display("⚠️ Disconnected.")
                break
            try:
                encrypted_data_b64, vernam_key_b64, hash_value = packet.split(b":::", 2)
                encrypted_data = base64.b64decode(encrypted_data_b64)
                vernam_key = base64.b64decode(vernam_key_b64)

                rsa_decrypted = cipher_rsa.decrypt(encrypted_data)
                calculated_hash = hashlib.sha256(rsa_decrypted).hexdigest()

                self.display(f"  • Received Hash: {hash_value.decode()}")
                self.display(f"  • Calculated Hash: {calculated_hash}")

                if calculated_hash != hash_value.decode():
                    self.display("⚠️ Hash mismatch! Message may be tampered.")
                    continue

                plaintext, steps = decrypt_full_message(rsa_decrypted, vernam_key)

                self.display("\n🔐 === Decryption Details ===")
                self.display(f"  • Encrypted (base64): {encrypted_data_b64.decode()}")
                self.display(f"  • Vernam Key (base64): {vernam_key_b64.decode()}")
                for step, value in steps.items():
                    self.display(f"  • {step}: {value}")
                self.display(f"\n👤 Client: {steps['After undoing Monoalphabetic']}")

            except Exception as e:
                self.display(f"⚠️ Error: {str(e)}")
                break

    def send_message(self):
        message = self.entry.get()
        if message:
            try:
                encoded_msg = message.encode()
                header = struct.pack('>I', len(encoded_msg))
                self.client_socket.sendall(header + encoded_msg)
                self.display(f"📤 Server: {message}")
                self.entry.delete(0, tk.END)
            except:
                self.display("⚠️ Error sending message.")

if __name__ == '__main__':
    root = tk.Tk()
    app = ChatServer(root)
    root.mainloop()
