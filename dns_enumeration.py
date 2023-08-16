import socket

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def dnsrec(domain):
    result = {'dns': [], 'dmarc': []}
    print(f'\n{Y}[!] Starting DNS Enumeration...{W}\n')
    types = ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'TXT']

    # Set a timeout value in seconds
    timeout = 10

    dns_server = '8.8.8.8'  # Google DNS server

    for record_type in types:
        try:
            resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            resolver.settimeout(timeout)
            resolver.connect((dns_server, 53))
            query = bytes([len(domain)]) + domain.encode('utf-8') + bytes([0]) + bytes([types.index(record_type) + 1]) + bytes([0]) + bytes([1])
            resolver.send(query)
            data = resolver.recv(4096)
            resolver.close()
            print(f'{G}[+] {C}{record_type}:{W} {data[13:].decode("utf-8")}')
            result['dns'].append(f'{record_type}: {data[13:].decode("utf-8")}')
        except (socket.gaierror, socket.timeout):
            pass

    dmarc_target = f'_dmarc.{domain}'
    try:
        resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        resolver.settimeout(timeout)
        resolver.connect((dns_server, 53))
        dmarc_query = bytes([len(dmarc_target)]) + dmarc_target.encode('utf-8') + bytes([0]) + bytes([16]) + bytes([0]) + bytes([1])
        resolver.send(dmarc_query)
        data = resolver.recv(4096)
        resolver.close()
        print(f'{G}[+] {C}DMARC:{W} {data[13:].decode("utf-8")}')
        result['dmarc'].append(f'DMARC: {data[13:].decode("utf-8")}')
    except (socket.gaierror, socket.timeout):
        pass

    if result['dns'] or result['dmarc']:
        result['exported'] = True
    else:
        print(f'\n{R}[-] {C}No DNS Records or DMARC Record Found!{W}')
        result['exported'] = False

    return result

if __name__ == "__main__":
    target_domain = input("Enter the domain to perform DNS enumeration: ")
    result = dnsrec(target_domain)
    print(result)
