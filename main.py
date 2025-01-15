import socket
import time
import config

# Configuration
TARGET_IP = config.IP_ADDRESS
PORT_RANGE = range(1, 1024)
SCAN_THRESHOLD = 5
TIME_WINDOW = 10

def detect_port_scan():
    print("Monitoring network and ports...")
    connection_attempts = {}
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            for port in PORT_RANGE:
                result = s.connect_ex((TARGET_IP, port))
                print(f"Checking next port...{PORT_RANGE[port]}")
                if result == 0:
                    if port not in connection_attempts:
                        connection_attempts[port] = []
                    connection_attempts[port].append(time.time())

            for port, timestamps in connection_attempts.items():
                if len(timestamps) >= SCAN_THRESHOLD:
                    recent_attempts = [t for t in timestamps if t > time.time() - TIME_WINDOW]
                    if len(recent_attempts) >= SCAN_THRESHOLD:
                        print(f"Alert: Potential port scan detected on {TARGET_IP}:{port}")
                        connection_attempts[port] = []

            print("Quick break until next scan...")
            time.sleep(1)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    detect_port_scan() 