import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def perform_web_recon(website_url):
    # Set timeout values in seconds
    timeout = 10

    # Send a GET request to the website
    response = requests.get(website_url, timeout=timeout)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Lists to store URLs of different types of files
        js_files = []
        css_files = []
        html_files = []
        php_files = []
        image_files = []
        internal_links = set()
        external_links = set()

        # Regular expression pattern to match file extensions
        file_extension_pattern = r'\.([a-zA-Z0-9]+)$'

        # Find all <script> tags and extract src URLs
        for script_tag in soup.find_all('script', src=True):
            src = script_tag['src']
            js_files.append(src)

        # Find all <link> tags with rel="stylesheet" and extract href URLs
        for link_tag in soup.find_all('link', rel='stylesheet', href=True):
            href = link_tag['href']
            css_files.append(href)

        # Find all <a> tags and extract href URLs
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if re.search(file_extension_pattern, href):
                extension = re.search(file_extension_pattern, href).group(1)
                if extension == 'html':
                    html_files.append(href)
                elif extension == 'php':
                    php_files.append(href)
                else:
                    image_files.append(href)
            else:
                if href.startswith('#'):
                    continue
                full_url = urljoin(website_url, href)
                parsed_url = urlparse(full_url)
                if parsed_url.netloc == urlparse(website_url).netloc:
                    internal_links.add(full_url)
                else:
                    external_links.add(full_url)

        # Print the URLs
        print(f"{G}[+] {C}JS Files:{W}")
        for js_file in js_files:
            print(js_file)

        print(f"\n{G}[+]{C}CSS Files:{W}")
        for css_file in css_files:
            print(css_file)

        print(f"\n{G}[+] {C}HTML Files:{W}")
        for html_file in html_files:
            print(html_file)

        print(f"\n{G}[+] {C}PHP Files:{W}")
        for php_file in php_files:
            print(php_file)

        print(f"\n{G}[+] {C}Image Files:{W}")
        for image_file in image_files:
            print(image_file)

        print(f"\n{G}[+] {C}Internal Links:{W}")
        for internal_link in internal_links:
            print(internal_link)

        print(f"\n{G}[+] {C}External Links:{W}")
        for external_link in external_links:
            print(external_link)

        # Directory search and print details
        directory_search = website_url + "/directory"  # Replace with the directory you want to search
        directory_response = requests.get(directory_search, timeout=timeout)

        if directory_response.status_code == 200:
            directory_soup = BeautifulSoup(directory_response.content, 'html.parser')
            directory_links = []

            # Find all <a> tags in the directory page
            for a_tag in directory_soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(directory_search, href)
                directory_links.append(full_url)

            print("\n{G}[+] {C}Directory Links:")
            for directory_link in directory_links:
                print(directory_link)

        else:
            print("\nFailed to fetch directory. Status code:", directory_response.status_code)

        # Print the counts
        print(f"\n{G}[+] {C}Total JS Files:{W}", len(js_files))
        print(f"{G}[+] {C}Total CSS Files:{W}", len(css_files))
        print(f"{G}[+] {C}Total HTML Files:{W}", len(html_files))
        print(f"{G}[+] {C}Total PHP Files:{W}", len(php_files))
        print(f"{G}[+] {C}Total Image Files:{W}", len(image_files))
        print(f"{G}[+] {C}Total Internal Links:{W}", len(internal_links))
        print(f"{G}[+] {C}Total External Links:{W}", len(external_links))

    else:
        print(f"{R}Failed to fetch the website. Status code:", response.status_code)

if __name__ == "__main__":
    target_website = "https://spyboy.blog"  # Replace with your desired URL
    perform_web_recon(target_website)