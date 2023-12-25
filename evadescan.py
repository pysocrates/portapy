import nmap
import json

def evasion_scan(ip, output_file):
    nm = nmap.PortScanner()

    # Evasion Techniques
    # Fragment packets (-f)
    # Use decoys (-D RND:10)
    # Idle zombie scan (-sI)
    # Timing template (-T)
    arguments = '-f -D RND:10 -T2'

    # Scanning common ports with evasion techniques
    nm.scan(ip, '1-1024', arguments=arguments)

    scan_data = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = nm[host][proto][port]
                if port_info['state'] == 'open':
                    service_info = {
                        'port': port,
                        'service': port_info['name'],
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extra_info': port_info.get('extrainfo', '')
                    }
                    scan_data[port] = service_info

    with open(output_file, 'w') as file:
        json.dump(scan_data, file, indent=4)

    return scan_data

# Example Usage
target_ip = '192.168.1.1'  # Replace with the target IP
output_file = 'evasion_scan_results.json'
results = evasion_scan(target_ip, output_file)
print(f"Scan results saved to {output_file}")