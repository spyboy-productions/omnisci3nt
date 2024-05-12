import requests
from colorama import init, Fore
import threading
import time

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

init()

def find_subdomains(domain, filename, timeout=20):
    subdomains_found = []
    subdomains_lock = threading.Lock()

    def check_subdomain(subdomain):
        subdomain_url = f"https://{subdomain}.{domain}"

        try:
            response = requests.get(subdomain_url, timeout=timeout)
            if response.status_code == 200:
                with subdomains_lock:
                    subdomains_found.append(subdomain_url)
                    print(f"{Fore.GREEN}Subdomain Found [+]: {subdomain_url}{Fore.RESET}")
        except requests.exceptions.RequestException as e:
            if "Max retries exceeded with url" in str(e):
                pass

    with open(filename, "r") as file:
        subdomains = [line.strip() for line in file.readlines()]

    print(f"{Y}Starting threads...")
    start_time = time.time()

    threads = []
    for subdomain in subdomains:
        thread = threading.Thread(target=check_subdomain, args=(subdomain,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"{G}[+] {C}Total Subdomains Scanned:{W} 781")
    print(f"{G}[+] {C}Total Subdomains Found:{W} {len(subdomains_found)}")
    print(f"{G}[+] {C}Time taken:{W} {elapsed_time:.2f} seconds")
    print("\nSubdomains Found Links:\n")
    for link in subdomains_found:
        print(link)

if __name__ == "__main__":
    domain = "youtube.com"
    filename = "wordlist2.txt"
    print(f"{Y}Scanning for subdomains. Please wait...{Fore.RESET}")
    find_subdomains(domain, filename)
