import socket
import dns.resolver

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def get_domain_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"{G}[+] {C}IP Address:{W} {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"{R}[-] {C}Could not resolve IP address for the domain.{W}")
        return None

def dnsrec(domain):
    ip_address = get_domain_ip(domain)
    if ip_address:
        result = {'dns': [], 'dmarc': []}
        print(f'\n{Y}[~] Starting DNS Enumeration...{W}\n')
        types = ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'TXT']

        # Set a timeout value in seconds
        timeout = 10

        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for record_type in types:
            try:
                response = resolver.query(domain, record_type)
                for answer in response:
                    print(f'{G}[+] {C}{record_type}:{W} {answer}')
                    result['dns'].append(f'{record_type}: {answer}')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass

        dmarc_target = f'_dmarc.{domain}'
        try:
            dmarc_response = resolver.query(dmarc_target, 'TXT')
            for answer in dmarc_response:
                print(f'{G}[+] {C}DMARC:{W} {answer}')
                result['dmarc'].append(f'DMARC: {answer}')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
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
