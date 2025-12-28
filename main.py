import socket
import subprocess
import threading
import sys
import argparse
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network, ip_address

print_lock = threading.Lock()

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S"
}

def ping_host(ip, timeout=1):
    """
    ICMP-based host discovery.
    Returns True if ICMP reply is received.
    """
    try:
        param = "-n" if sys.platform.startswith("win") else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-w", str(timeout * 1000), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False

def scan_port(ip, port, timeout=0.5):
    """
    Scan a single port.
    Returns (port, service, banner) if open, else None.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        service = COMMON_PORTS.get(port, "Unknown")
        banner = ""
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")  # Try HTTP banner
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            pass
        s.close()
        return (port, service, banner[:50])  # Limit banner length
    except:
        return None

def scan_ports(ip, ports, timeout=0.5, verbose=False):
    """
    Scan multiple ports.
    Returns list of open ports with details.
    """
    open_ports = []
    for port in ports:
        result = scan_port(ip, port, timeout)
        if result:
            open_ports.append(result)
            if verbose:
                with print_lock:
                    print(f"[+] Port {result[0]} ({result[1]}) open on {ip}")
                    if result[2]:
                        print(f"    └─ Banner: {result[2]}")
    return open_ports

def scan_host(ip, ports, timeout=0.5, verbose=False):
    """
    Scan a single host: ping and port scan.
    Returns dict with results.
    """
    icmp_alive = ping_host(ip, timeout)
    open_ports = scan_ports(ip, ports, timeout, verbose)

    result = {
        "ip": ip,
        "icmp_alive": icmp_alive,
        "open_ports": [{"port": p[0], "service": p[1], "banner": p[2]} for p in open_ports]
    }

    with print_lock:
        if icmp_alive or open_ports:
            status = "reachable (ICMP)" if icmp_alive else "responding (TCP)"
            print(f"[+] Host {status}: {ip}")
            for port_info in open_ports:
                print(f"    └─ Port {port_info['port']} ({port_info['service']}) open")
                if port_info['banner']:
                    print(f"        └─ Banner: {port_info['banner']}")
        else:
            if verbose:
                print(f"[-] Host appears down: {ip}")

    return result

def generate_ip_range(start_ip, end_ip):
    """
    Generate list of IPs from start to end.
    """
    try:
        start = ip_address(start_ip)
        end = ip_address(end_ip)
        if start > end:
            raise ValueError("Start IP must be less than or equal to end IP")
        ips = []
        current = start
        while current <= end:
            ips.append(str(current))
            current = current + 1
        return ips
    except Exception as e:
        print(f"Error generating IP range: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("start_ip", help="Start IP address")
    parser.add_argument("end_ip", help="End IP address")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated or range, e.g., 1-100)", default="21,22,23,80,443")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Timeout for connections (seconds)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file (JSON or CSV)")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")

    args = parser.parse_args()

    # Parse ports
    ports = []
    for part in args.ports.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    ips = generate_ip_range(args.start_ip, args.end_ip)

    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_host, ip, ports, args.timeout, args.verbose): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    # Output results
    if args.output:
        if args.format == "json":
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
        elif args.format == "csv":
            with open(args.output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "ICMP Alive", "Open Ports"])
                for result in results:
                    ports_str = "; ".join([f"{p['port']} ({p['service']})" for p in result["open_ports"]])
                    writer.writerow([result["ip"], result["icmp_alive"], ports_str])
        print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()
