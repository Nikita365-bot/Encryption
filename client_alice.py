import socket
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = '127.0.0.1'
PORT = 5560  

# Load Bob's public key
with open("bob_public.pem", "rb") as f:
    bob_public_key = serialization.load_pem_public_key(f.read())

# Generate AES session key
session_key = os.urandom(32)  # AES-256

# Encrypt AES session key with Bob's public key
encrypted_session_key = bob_public_key.encrypt(
    session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
client.recv(1024)  # USERNAME? prompt
client.send(b"alice")
client.send(encrypted_session_key)
print(" AES session key sent to Bob (RSA-encrypted).")

messages = []

def encrypt_message(message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ct

try:
    while True:
        msg = input("Enter a message for Bob: ")
        if msg.lower() == "exit":
            break
        ciphertext = encrypt_message(msg)
        client.send(ciphertext)
        messages.append({
            "ciphertext": ciphertext.hex(),
            "plaintext": msg
        })
        with open("alice_messages.json", "w") as f:
            json.dump(messages, f, indent=4)
except KeyboardInterrupt:
    print("\n Exiting client.")
finally:
    client.close()
