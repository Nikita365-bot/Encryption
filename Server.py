import socket
import threading

HOST = '127.0.0.1'
PORT = 5560  
clients = {}  

def handle_client(client_socket):
    try:
        client_socket.send(b"USERNAME?")
        username = client_socket.recv(1024).decode()
        clients[username] = client_socket
        print(f"👤 {username} connected.")

        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            # Send to all other clients
            for user, sock in clients.items():
                if sock != client_socket:
                    sock.send(data)

    except ConnectionResetError:
        pass
    finally:
        print(f" {username} disconnected.")
        if username in clients:
            del clients[username]
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"🖥 Server running on port {PORT}...")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()

if __name__ == "__main__":
    start_server()
