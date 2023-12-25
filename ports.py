import socket
import ipaddress

def scan_network(ip, ports=None):
    if ports is None:
        ports = range(1, 1024)  # scan common ports if none provided
    open_ports = []
    for port in ports:
        print(f"Scanning IP: {ip}, Port: {port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((str(ip), port))
        if result == 0:
            print(f"\033[92mPort {port} is open\033[0m")  # output in green
            open_ports.append(port)
        else:
            print(f"Port {port} is closed")
        sock.close()
    return open_ports

def scan_range(start, end, step):
    results = {}
    start = int(ipaddress.IPv4Address(start))
    end = int(ipaddress.IPv4Address(end))
    for ip in range(start, end + 1, step):
        result = scan_network(ipaddress.IPv4Address(ip))
        results[ipaddress.IPv4Address(ip)] = result
    return results

start_ip, end_ip, step = ipaddress.IPv4Address('192.168.1.1'), ipaddress.IPv4Address('192.168.1.255'), 1
results = scan_range(start_ip, end_ip, step)

for ip, result in results.items():
    print(f"IP Address: {ip}")
    print(f"Open Ports: {result}")
    print()
