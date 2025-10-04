# === crypto_utils.py ===

import base64
from hashlib import sha256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# === Cipher Algorithms ===
def mono_encrypt(text):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    table = str.maketrans(alphabet, key)
    return text.upper().translate(table)

def mono_decrypt(text):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    table = str.maketrans(key, alphabet)
    return text.translate(table)

def vigenere_encrypt(text, key):
    result = ''
    key = key.upper()
    for i, c in enumerate(text):
        if c.isalpha():
            offset = ord('A')
            shift = ord(key[i % len(key)]) - offset
            result += chr((ord(c.upper()) - offset + shift) % 26 + offset)
        else:
            result += c
    return result

def vigenere_decrypt(text, key):
    result = ''
    key = key.upper()
    for i, c in enumerate(text):
        if c.isalpha():
            offset = ord('A')
            shift = ord(key[i % len(key)]) - offset
            result += chr((ord(c.upper()) - offset - shift) % 26 + offset)
        else:
            result += c
    return result

def swap_characters(s):
    s = list(s)
    for i in range(0, len(s) - 1, 2):
        s[i], s[i + 1] = s[i + 1], s[i]
    return ''.join(s)

def undo_swap(s):
    return swap_characters(s)  # Reversible

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_decrypt(data, key):
    return xor_encrypt(data, key)  # Reversible

def transposition_encrypt(s):
    result = []
    for i in range(0, len(s), 4):
        block = s[i:i+4]
        result.extend(block[::-1])
    return ''.join(result)

def reverse_transposition(s):
    return transposition_encrypt(s)  # Reversible

def encrypt_message(plaintext, vernam_key, public_key):
    steps = {}

    # Step 3: Monoalphabetic
    step3 = mono_encrypt(plaintext)
    steps['Monoalphabetic'] = step3

    # Step 4: Vigenère
    vigenere_key = "KEY"
    step4 = vigenere_encrypt(step3, vigenere_key)
    steps['Vigenere'] = step4

    # Step 5: Swap characters
    step5 = swap_characters(step4)
    steps['Swapped'] = step5

    # Step 6: Vernam XOR (to bytes)
    step6 = xor_encrypt(step5.encode(), vernam_key)
    steps['Vernam'] = base64.b64encode(step6).decode()

    # Step 7: Transposition
    step7 = transposition_encrypt(step6.decode(errors='ignore'))
    steps['Transposition'] = step7

    # Step 8: RSA Encrypt final result
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted = cipher_rsa.encrypt(step7.encode())
    steps['Final RSA Ciphertext'] = base64.b64encode(encrypted).decode()

    # Hash
    steps['Hash'] = sha256(step6).hexdigest()

    return encrypted, steps

def decrypt_full_message(rsa_decrypted_bytes, vernam_key):
    steps = {}

    # Step 3: Reverse Transposition
    step3 = reverse_transposition(rsa_decrypted_bytes.decode(errors='ignore'))
    steps['Reverse Transposition'] = step3

    # Step 4: Reverse Vernam
    step4_bytes = xor_decrypt(step3.encode(), vernam_key)
    try:
        step4 = step4_bytes.decode()
    except:
        step4 = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in step4_bytes)
    steps['After XOR (Vernam)'] = step4

    # Step 5: Undo Swapping
    step5 = undo_swap(step4)
    steps['Undo Swapping'] = step5

    # Step 6: Vigenère Decryption
    step6 = vigenere_decrypt(step5, "KEY")
    steps['Vigenere Decryption'] = step6

    # Step 7: Monoalphabetic Decryption
    final_plaintext = mono_decrypt(step6)
    steps['Final Plaintext'] = final_plaintext

    return final_plaintext, steps
