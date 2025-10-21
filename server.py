import socket
import threading

HOST = '127.0.0.1'
PORT = 5560

clients = {}  # username -> socket


def handle_client(conn, addr):
    try:
        # Send username prompt (so client.recv(1024) in Alice/Bob matches)
        conn.send(b"USERNAME?")
        username = conn.recv(1024).decode().strip()
        clients[username] = conn
        print(f"👤 {username} connected.")

        # Handle special case: Alice sends an encrypted AES key to Bob
        if username == "alice":
            encrypted_session_key = conn.recv(4096)
            print(f" Encrypted AES session key received from Alice ({len(encrypted_session_key)} bytes).")
            # Forward key to Bob if connected
            if "bob" in clients:
                clients["bob"].send(encrypted_session_key)
                print(" Forwarded encrypted AES session key to Bob.")
            else:
                print(" Bob not connected. Cannot forward AES key yet.")

        # Handle messages
        while True:
            data = conn.recv(4096)
            if not data:
                break

            # Log ciphertext in hex
            print(f"[ENCRYPTED MESSAGE] from {username}: {data.hex()}")

            # Forward ciphertext to the other client
            for user, client_conn in clients.items():
                if user != username:
                    try:
                        client_conn.send(data)
                    except Exception as e:
                        print(f" Error sending to {user}: {e}")

    except Exception as e:
        print(f" Error with {addr}: {e}")

    finally:
        if username in clients:
            del clients[username]
        conn.close()
        print(f" {username} disconnected.")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"🖥 Server running on port {PORT}...")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
