import requests
import threading
import socket
import whois
from urllib.parse import urljoin
from tqdm import tqdm
from requests.exceptions import Timeout

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow


def find_admin_panels(target_url, paths, num_threads):
    target_url = target_url.rstrip("/")  # Remove trailing slashes

    def get_domain(url):
        return url.split("//")[-1].split("/")[0]

    found_admin_panels = []  # To store found admin panel links

    def scan(paths, progress_bar):
        for path in paths:
            try:
                full_url = urljoin(target_url, path)
                r = requests.get(full_url, timeout=3)
                http = r.status_code
                if http == 200:
                    print(
                        f"\n  \033[1;32m[+]\033[0m Potential Admin panel found: {full_url}"
                    )
                    found_admin_panels.append(full_url)
                elif http == 302:
                    print(
                        f"  \033[1;32m[+]\033[0m Potential EAR vulnerability found: {full_url}"
                    )

            # except Timeout:
            # print(f"{Y}[!] Timeout on: {full_url}{W}")

            except Exception:
                pass  # Ignore errors
            progress_bar.update(1)

    def divide_and_scan(paths, num_threads):
        path_chunks = [
            paths[i : i + num_threads] for i in range(0, len(paths), num_threads)
        ]
        total_paths = len(paths)

        with tqdm(
            total=total_paths,
            desc="Scanning Admin Panels",
            ncols=100,
            bar_format="{l_bar}{bar} {n_fmt}/{total_fmt}",
        ) as progress_bar:
            threads = []
            for chunk in path_chunks:
                t = threading.Thread(target=scan, args=(chunk, progress_bar))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

    def generate_admin_panel_link(domain):
        return f"http://{domain}/admin/"

    paths = paths.split("\n")
    paths = [path.strip() for path in paths]

    divide_and_scan(paths, num_threads)

    result = []

    if found_admin_panels:
        result.append("\n\033[1;32mPotential Admin Panels Found:\033[0m")
        for admin_panel in found_admin_panels:
            result.append(admin_panel)
    else:
        try:
            domain = get_domain(target_url)
            domain_ip = socket.gethostbyname(domain)
            domain_info = whois.whois(domain)
            hosting_location = domain_info.org

            if hosting_location:
                result.append(
                    f"{G}[+] {C} The website is hosted by: {hosting_location}"
                )
            else:
                potential_admin_panel_link = generate_admin_panel_link(domain)
                result.append(
                    f"{G}[+] {Y} Try this potential admin panel link:{W} {potential_admin_panel_link}"
                )
                potential_admin_panel_link = generate_admin_panel_link(domain_ip)
                result.append(
                    f"{G}[+] {Y} Another possible admin panel link:{W} {potential_admin_panel_link}"
                )

        except Exception as e:
            result.append(
                f"{G}[+] {R} Could not determine hosting location. Error: {e}"
            )

    return result
