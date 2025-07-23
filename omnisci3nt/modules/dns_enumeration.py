import socket
import dns.resolver

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


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
        result = {"dns": [], "dmarc": []}
        print(f"\n{Y}[~] Starting DNS Enumeration...{W}\n")
        types = ["A", "AAAA", "CAA", "CNAME", "MX", "NS", "TXT"]

        # Set a timeout value in seconds
        timeout = 3

        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for record_type in types:
            try:
                response = resolver.query(domain, record_type)
                for answer in response:
                    print(f"{G}[+] {C}{record_type}:{W} {answer}")
                    result["dns"].append(f"{record_type}: {answer}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass

        dmarc_target = f"_dmarc.{domain}"
        try:
            dmarc_response = resolver.query(dmarc_target, "TXT")
            for answer in dmarc_response:
                print(f"{G}[+] {C}DMARC:{W} {answer}")
                result["dmarc"].append(f"DMARC: {answer}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass

        if result["dns"] or result["dmarc"]:
            result["exported"] = True
        else:
            print(f"\n{R}[-] {C}No DNS Records or DMARC Record Found!{W}")
            result["exported"] = False

        return result


def check_mx_spoof(domain):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
        print(f"{G}[+] {C}MX Records:{W} {', '.join(mx_hosts)}")
        # List of generic/free mail providers
        generic_providers = [
            'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'yahoo.com',
            'aol.com', 'zoho.com', 'mail.com', 'protonmail.com', 'icloud.com',
        ]
        risky = False
        for mx in mx_hosts:
            for provider in generic_providers:
                if provider in mx:
                    print(f"{R}[!] Warning: MX record points to generic provider: {mx} (possible spoofing risk)")
                    risky = True
        if not mx_hosts:
            print(f"{R}[!] No MX records found. Domain may be easily spoofed!")
        elif not risky:
            print(f"{G}[+] {C}No obvious spoofing risk detected in MX records.{W}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{R}[!] No MX records found. Domain may be easily spoofed!")
    except Exception as e:
        print(f"{R}[!] Error checking MX records: {e}{W}")


if __name__ == "__main__":
    target_domain = input("Enter the domain to perform DNS enumeration: ")
    result = dnsrec(target_domain)
    print(result)
