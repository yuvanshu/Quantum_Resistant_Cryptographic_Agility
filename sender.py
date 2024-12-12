import socket
import threading
import time
import psutil

class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = None
        self.start_time = None
        self.message_count = 0

    def connect(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")
        self.start_time = time.time()

    def send_message(self, message):
        self.client_socket.send(message.encode())
        self.message_count += 1

    def receive_message(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if message:
                    print(f"Server: {message}")
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
    client = ChatClient("localhost", 12345)
    client.connect()

    receive_thread = threading.Thread(target=client.receive_message)
    receive_thread.start()

    try:
        while True:
            message = input("You: ")
            if message.lower() == 'quit':
                break
            client.send_message(message)
    except KeyboardInterrupt:
        pass
    finally:
        client.get_metrics()
        client.client_socket.close()