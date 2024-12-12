import socket
import threading
import time
import psutil

class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.start_time = None
        self.message_count = 0

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")
        self.client_socket, addr = self.server_socket.accept()
        print(f"Connected to client at {addr}")
        self.start_time = time.time()

    def send_message(self, message):
        self.client_socket.send(message.encode())
        self.message_count += 1

    def receive_message(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if message:
                    print(f"Client: {message}")
                    self.message_count += 1
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def get_metrics(self):
        end_time = time.time()
        execution_time = end_time - self.start_time
        memory_usage = psutil.virtual_memory().percent
        network_stats = psutil.net_io_counters()
        bandwidth = (network_stats.bytes_sent + network_stats.bytes_recv) / execution_time
        latency = execution_time / self.message_count if self.message_count > 0 else 0

        print(f"\nMetrics:")
        print(f"Execution Time: {execution_time:.2f} seconds")
        print(f"Memory Utilization: {memory_usage:.2f}%")
        print(f"Bandwidth: {bandwidth:.2f} bytes/second")
        print(f"Latency: {latency:.4f} seconds/message")

if __name__ == "__main__":
    server = ChatServer("localhost", 12345)
    server.start()

    receive_thread = threading.Thread(target=server.receive_message)
    receive_thread.start()

    try:
        while True:
            message = input("You: ")
            if message.lower() == 'quit':
                break
            server.send_message(message)
    except KeyboardInterrupt:
        pass
    finally:
        server.get_metrics()
        server.client_socket.close()
        server.server_socket.close()