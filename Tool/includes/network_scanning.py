import socket
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    def __init__(self, target_ip, port_range=(1, 65535)):
        self.target_ip = target_ip
        self.port_range = port_range

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1) 
                result = s.connect_ex((self.target_ip, port))
                if result == 0:
                    return f"Port {port}: OPEN"
                else:
                    return f"Port {port}: CLOSED"
        except Exception as e:
            return f"Port {port}: ERROR ({str(e)})"

    def scan_ports(self, max_threads=50):
        open_ports = []
        with ThreadPoolExecutor(max_threads) as executor:
            results = executor.map(self.scan_port, range(self.port_range[0], self.port_range[1] + 1))
            for result in results:
                if "OPEN" in result:
                    open_ports.append(result)
                    print(f"Found open port: {result}")  
        return open_ports

    def service_detection(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.target_ip, port))
                s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                response = s.recv(1024)
                return response.decode("utf-8", errors="ignore")
        except Exception as e:
            return f"Error detecting service on port {port}: {str(e)}"
