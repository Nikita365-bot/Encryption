import socket
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = '127.0.0.1'
PORT = 5560  

# Load Bob's private key
with open("bob_private.pem", "rb") as f:
    bob_private_key = serialization.load_pem_private_key(f.read(), password=None)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
client.recv(1024)  # USERNAME? prompt
client.send(b"bob")

# Receive encrypted AES session key
encrypted_session_key = client.recv(4096)
session_key = bob_private_key.decrypt(
    encrypted_session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("🔐 AES session key received and decrypted.")

messages = []

def decrypt_message(ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

try:
    while True:
        data = client.recv(4096)
        if not data:
            print("⚠️ Connection closed by server.")
            break
        print(f"[Encrypted]: {data.hex()}")
        try:
            plaintext = decrypt_message(data)
            print(f"[Decrypted]: {plaintext}")
        except Exception as e:
            print(f" Error decrypting message: {e}")
            plaintext = "<decryption failed>"
        messages.append({
            "ciphertext": data.hex(),
            "plaintext": plaintext
        })
        with open("bob_messages.json", "w") as f:
            json.dump(messages, f, indent=4)
except KeyboardInterrupt:
    print("\n Exiting client.")
finally:
    client.close()
