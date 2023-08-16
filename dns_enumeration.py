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
    resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver.connect((dns_server, 53))

    for record_type in types:
        try:
            response = resolver.sendto(domain.encode('utf-8'), (dns_server, 53))
            data, _ = resolver.recvfrom(4096)
            print(f'{G}[+] {C}{record_type}:{W} {data.decode("utf-8")}')
            result['dns'].append(f'{record_type}: {data.decode("utf-8")}')
        except (socket.gaierror, socket.timeout):
            pass

    dmarc_target = f'_dmarc.{domain}'
    try:
        dmarc_response = resolver.sendto(dmarc_target.encode('utf-8'), (dns_server, 53))
        data, _ = resolver.recvfrom(4096)
        print(f'{G}[+] {C}DMARC:{W} {data.decode("utf-8")}')
        result['dmarc'].append(f'DMARC: {data.decode("utf-8")}')
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
