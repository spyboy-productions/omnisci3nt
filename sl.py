import ssl
import socket

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def get_certificate_info(hostname, port=443, timeout=10):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            certificate = ssock.getpeercert()

    return certificate


def print_certificate_info(certificate):
    print(f'\n{Y}[~] SSL Certificate Information  :{W}\n')
    #print(f"{G}[+] {C}Certificate Information:")
    print(f"{G}[+] {C}Subject:{W}", dict(x[0] for x in certificate['subject']))
    print(f"{G}[+] {C}Issuer:{W}", dict(x[0] for x in certificate['issuer']))
    print(f"{G}[+] {C}Valid From:{W}", certificate['notBefore'])
    print(f"{G}[+] {C}Valid Until:{W}", certificate['notAfter'])


if __name__ == "__main__":
    target_host = input("Enter the website hostname: ")
    certificate_info = get_certificate_info(target_host)
    print_certificate_info(certificate_info)
