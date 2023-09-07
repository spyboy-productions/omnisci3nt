import sys
import socket
from scapy.layers.inet import IP, ICMP, sr

def traceroute(domain):
    try:
        target_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print("Invalid domain or IP address.")
        sys.exit(1)

    max_hops = 30  # Maximum number of hops to trace

    print(f"Traceroute to {domain} ({target_ip}), {max_hops} hops max")

    for ttl in range(1, max_hops + 1):
        packet = IP(dst=target_ip, ttl=ttl) / ICMP()
        responses, _ = sr(packet, verbose=False, timeout=1)

        if responses:
            response = responses[0][1]
            print(f"{ttl}: {response.src}")
            if response.src == target_ip:
                break
        else:
            print(f"{ttl}: *")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python traceroute.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    traceroute(domain)

''' to run from another file
# main.py
from traceroute import traceroute  # Import the traceroute function

def main():
    domain = "x.com"  # Replace with the domain you want to traceroute
    traceroute(domain)  # Call the traceroute function

if __name__ == "__main__":
    main()
'''
