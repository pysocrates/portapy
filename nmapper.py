
# This script uses the nmap library to perform a network scan on a given range of IP address.
# The scan_network function takes an IP address as input. It creates an instance of nmap.PortScanner and uses it to scan the IP address. 
# The function uses several evasion techniques to avoid detection:
#      - Fragmented packets (-f)
#      - Decoy IPs (-D RND:10)
#      - Timing template (-T2)

These arguments are passed to the nm.scan method along with the IP address and the range of ports to scan (1-1024).

The function initializes a dictionary with the IP address and status. If the host is up, it updates the status and gathers OS and device info.

The OS and device info are obtained from the 'osclass' field of the scan results. This information is added to the 'device_info' field of the scan_data dictionary.

The function then returns the scan_data dictionary, which contains the IP address, status, open ports, and device info.


import nmap
import ipaddress
import json

def scan_network(ip):
    nm = nmap.PortScanner()
    print(f"Scanning IP: {ip} with evasion techniques")

    # Evasion Techniques
    # Fragmented packets (-f)
    # Decoy IPs (-D RND:10)
    # Timing template (-T2)
    arguments = '-sV -O -f -D RND:10 -T2'

    nm.scan(str(ip), '1-1024', arguments=arguments)

    scan_data = {'ip': str(ip), 'status': 'down', 'open_ports': {}, 'device_info': {}}
    if nm.all_hosts():
        scan_data['status'] = 'up'
        for host in nm.all_hosts():
            # Gathering OS and Device Info
            os_info = nm[host].get('osclass', [{}])[0]
            scan_data['device_info'] = {
                'os_name': os_info.get('osfamily', ''),
                'os_accuracy': os_info.get('accuracy', ''),
                'device_type': os_info.get('type', ''),
                'vendor': os_info.get('vendor', '')
            }
            print(f"Device Info: {scan_data['device_info']}")

            # Gathering Open Ports and Service Info
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    port_info = nm[host][proto][port]
                    print(f"Scanning IP: {ip}, Port: {port}")
                    if port_info['state'] == 'open':
                        print(f"\033[92mPort {port} is open\033[0m")  # output in green
                        service_info = {
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extra_info': port_info.get('extrainfo', '')
                        }
                        scan_data['open_ports'][port] = service_info
                    else:
                        print(f"Port {port} is closed")

    return scan_data

def scan_range(start, end, step):
    results = {}
    start = int(ipaddress.IPv4Address(start))
    end = int(ipaddress.IPv4Address(end))
    for ip in range(start, end + 1, step):
        network_info = scan_network(ipaddress.IPv4Address(ip))
        results[str(ipaddress.IPv4Address(ip))] = network_info
    return results

def write_results_to_json(file_name, data):
    with open(file_name, 'w') as file:
        json.dump(data, file, indent=4)

start_ip, end_ip, step = '192.168.0.0', '192.168.0.10', 1
scan_results = scan_range(start_ip, end_ip, step)

# Writing the results to a JSON file
output_file = 'network_scan_results.json'
write_results_to_json(output_file, scan_results)

print(f"Scan results saved to {output_file}")
