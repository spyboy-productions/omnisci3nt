import requests
from urllib.parse import urlparse, urljoin

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def check_website(website_url, timeout=10):
    robots_url = urljoin(website_url, "/robots.txt")
    robots_response = requests.get(robots_url, timeout=timeout)

    if robots_response.status_code == 200:
        print(f"{G}[+] {C}Robots.txt file exists.")
        print(f"{G}[+] {C}Robots.txt URL:", robots_url)
        robots_content = robots_response.text
        print(f"{G}[+] {C}Robots.txt content:")
        print(f"{W}{robots_content}")

        sitemap_directive = None
        for line in robots_content.split('\n'):
            if line.lower().startswith("sitemap:"):
                sitemap_directive = line.split(':', 1)[1].strip()
                break

        if sitemap_directive:
            sitemap_url = urljoin(website_url, sitemap_directive)
            sitemap_response = requests.get(sitemap_url, timeout=timeout)

            if sitemap_response.status_code == 200:
                print(f"\n{G}[+] {C}Sitemap URL:", sitemap_url)
                #print(f"{G}[+] {C}Sitemap content:")
                #print(f"{W}{sitemap_response.text}")
            else:
                print(f"\n{R}Failed to fetch sitemap. Status code:", sitemap_response.status_code)
        else:
            print(f"\n{R}No sitemap directive found in robots.txt.")
    else:
        print(f"{R}No robots.txt file found.")
