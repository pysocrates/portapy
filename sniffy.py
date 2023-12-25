from scapy.all import sniff
import json

def packet_callback(packet):
    try:
        # Extracting the IP addresses from packets
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            # Add the IP addresses to the set
            connected_ips.add(src_ip)
            connected_ips.add(dst_ip)
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    connected_ips = set()  # Using a set to avoid duplicates

    print("Starting network sniffing...")
    sniff(prn=packet_callback, store=False)  # Start sniffing

    # Save the results to a JSON file
    with open("connected_ips.json", "w") as file:
        json.dump(list(connected_ips), file, indent=4)

    print("Connected IP addresses saved to connected_ips.json")
