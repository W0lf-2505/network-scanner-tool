import socket
import subprocess
import threading
import sys

print_lock = threading.Lock()
COMMON_PORTS = [21, 22, 23, 80, 443]

def ping_host(ip):
    """
    ICMP-based host discovery.
    Returns True if ICMP reply is received.
    """
    try:
        param = "-n" if sys.platform.startswith("win") else "-c"
        result = subprocess.run(
            ["ping", param, "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False

def scan_ports(ip):
    """
    TCP port scan.
    Returns True if any port responds.
    """
    open_ports = []
    for port in COMMON_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

def scan_host(ip):
    icmp_alive = ping_host(ip)
    open_ports = scan_ports(ip)

    with print_lock:
        if icmp_alive:
            print(f"[+] Host reachable (ICMP): {ip}")
        elif open_ports:
            print(f"[+] Host responding (TCP): {ip}")
        else:
            print(f"[-] Host appears down: {ip}")

        for port in open_ports:
            print(f"    └─ Port {port} open")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python main.py <start_ip> <end_ip>")
        sys.exit(1)

    start_ip = sys.argv[1]
    end_ip = sys.argv[2]

    start = int(start_ip.split('.')[-1])
    end = int(end_ip.split('.')[-1])
    base_ip = ".".join(start_ip.split('.')[:-1])

    threads = []

    for i in range(start, end + 1):
        ip = f"{base_ip}.{i}"
        t = threading.Thread(target=scan_host, args=(ip,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
