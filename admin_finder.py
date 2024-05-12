import requests
import threading
from urllib.parse import urljoin
import whois
import socket

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def find_admin_panels(target_url, paths, num_threads):
    target_url = target_url.rstrip('/')  # Remove trailing slashes

    def get_domain(url):
        return url.split('//')[-1].split('/')[0]

    found_admin_panels = []  # To store found admin panel links

    def scan(paths):
        for path in paths:
            try:
                full_url = urljoin(target_url, path)
                r = requests.get(full_url)
                http = r.status_code
                if http == 200:
                    print(f'  \033[1;32m[+]\033[0m Potential Admin panel found: {full_url}')
                    found_admin_panels.append(full_url)  # Store found admin panel link
                elif http == 404:
                    print(f'  \033[1;31m[-]\033[1;m Not Found: {full_url}')
                elif http == 302:
                    print(f'  \033[1;32m[+]\033[0m Potential EAR vulnerability found: {full_url}')
                elif "login" in full_url.lower():
                    print(f'  \033[1;31m[-]\033[1;m Login Page Error: {full_url}')
            except Exception as e:
                pass  # Ignore errors

    def divide_and_scan(paths, num_threads):
        path_chunks = [paths[i:i + num_threads] for i in range(0, len(paths), num_threads)]

        threads = []
        for chunk in path_chunks:
            t = threading.Thread(target=scan, args=(chunk,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def generate_admin_panel_link(domain):
        return f'http://{domain}/admin/'

    paths = paths.split('\n')
    paths = [path.strip() for path in paths]

    divide_and_scan(paths, num_threads)

    result = []

    # Check if admin panels were found
    if found_admin_panels:
        result.append('\n\033[1;32mPotential Admin Panels Found:\033[0m')
        for admin_panel in found_admin_panels:
            result.append(admin_panel)
    else:
        result.append(f'\n{R}No potential admin panels found.\n')
        try:
            domain = get_domain(target_url)
            domain_ip = socket.gethostbyname(domain)

            domain_info = whois.whois(domain)
            hosting_location = domain_info.org

            if hosting_location:
                result.append(f'{G}[+] {C} The website is hosted by: {hosting_location}')
            else:
                #result.append(f'{G}\u2514\u27A4{R} Hosting location information not available.')
                potential_admin_panel_link = generate_admin_panel_link(domain)
                result.append(f'{G}[+] {Y} You can try the potential admin panel link:{W} {potential_admin_panel_link}')
                potential_admin_panel_link = generate_admin_panel_link(domain_ip)
                result.append(f'\n{G}[+] {Y} You can try the potential admin panel link:{W} {potential_admin_panel_link}')

        except Exception as e:
            result.append(f'{G}[+] {R} Failed to determine hosting location and generate a potential admin panel link. Error: {e}')

    return result
