# generate_keys.py

from Crypto.PublicKey import RSA

key = RSA.generate(2048)

private_key = key.export_key()
with open("server_private.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("server_public.pem", "wb") as f:
    f.write(public_key)

print("RSA key pair generated: server_private.pem & server_public.pem")
