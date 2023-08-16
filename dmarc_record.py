import dns.resolver
import re

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def fetch_dmarc_links(domain):
    try:
        print(f'\n{Y}[!] DMARC record :{W}\n')
        # Set a timeout value in seconds
        timeout = 10

        # Query DMARC record for the domain
        query_result = dns.resolver.resolve('_dmarc.' + domain, 'TXT', lifetime=timeout)

        # Extract DMARC policy from the TXT record
        dmarc_record = query_result.rrset[0].to_text()

        # Extract links using regular expressions
        link_pattern = r'https?://[^\s/$.?#].[^\s]*'
        links = re.findall(link_pattern, dmarc_record)

        return links
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print(f"{G}[+] {R}No DMARC record found for {domain}")
        return []
    except dns.exception.DNSException as e:
        print(f"{G}[+] {R}An error occurred: {e}")
        return []

if __name__ == "__main__":
    domain_to_check = input("Enter the domain to check DMARC record and fetch links: ")
    links = fetch_dmarc_links(domain_to_check)

    if links:
        print("Links found in DMARC record:")
        for link in links:
            print(link)
    else:
        print("No links found in DMARC record.")
