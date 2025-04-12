import sys
import requests
import whois
import time
from datetime import datetime
from pprint import pprint
import socket
import argparse
import signal
import threading
import os

from urllib.parse import urlparse
import ipaddress

from .modules.sl import get_certificate_info, print_certificate_info
from .modules.header import fetch_headers
from .modules.dns_enumeration import dnsrec
from .modules.dmarc_record import check_dmarc, Colors
from .modules.web_crawl import perform_web_recon
from .modules.robo_checker import check_website
from .modules.buildwith import analyze_website
from .modules.wayback import fetch_wayback_links
from .modules.social_media import extract_links_and_emails
from .modules.better_subdomain import (
    setup_config,
    get_api_keys,
    enumerate_subdomains,
    COLORS,
)
from .modules.dirtest import start_scan
from .modules.portscan import ps
from .modules.admin_finder import find_admin_panels

base_dir = os.path.dirname(os.path.abspath(__file__))

current_date = datetime.now().date()
formatted_date = current_date.strftime("%Y-%m-%d")

twitter_url = "https://spyboy.in/twitter"
discord = "https://spyboy.in/Discord"
github = "https://github.com/spyboy-productions/omnisci3nt"

VERSION = "1.0.5"

R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # white
Y = "\033[33m"  # yellow
M = "\033[35m"  # Magenta

banner = r"""                                               
                      .__              .__________         __   
  ____   _____   ____ |__| ______ ____ |__\_____  \  _____/  |_ 
 /  _ \ /     \ /    \|  |/  ___// ___\|  | _(__  < /    \   __\
(  <_> )  Y Y  \   |  \  |\___ \\  \___|  |/       \   |  \  |  
 \____/|__|_|  /___|  /__/____  >\___  >__/______  /___|  /__|  
             \/     \/        \/     \/          \/     \/ 
    Unveiling the Hidden Layers of the Web.     
"""


def print_program_banner():
    """
    prints the program banners
    """
    print(f"{R}{banner}{W}\n")
    print(f"{G}\u2514\u27a4 {Y}Version      : {W}{VERSION}")
    print(f"{G}\u2514\u27a4 {Y}Creator      : {W}Spyboy")
    print(f"{G}\u2514\u27a4 {Y}Twitter      : {W}{twitter_url}")
    print(f"{G}\u2514\u27a4 {Y}Discord      : {W}{discord}")
    print(f"{G}\u2514\u27a4 {Y}Github       : {W}{github}\n")
    print(
        f"____________________________________________________________________________\n"
    )


def print_recon_started_banner():
    banner = r"""
    +-+-+-+-+-+ +-+-+-+-+-+-+-+
    |R|e|c|o|n| |S|t|a|r|t|e|d|
    +-+-+-+-+-+ +-+-+-+-+-+-+-+
    """
    print(f"{G}{banner}")


def print_recon_completed_banner():
    banner = r"""
    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
    |R|e|c|o|n| |c|o|m|p|l|e|t|e|d|
    +-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
    """
    print(f"{M}{banner}")


# Global flag to handle graceful shutdown
shutdown_flag = threading.Event()


def signal_handler(sig, frame):
    """Handles termination signals like CTRL+C."""
    print(f"\n{R}[!] Caught interrupt signal. Shutting down gracefully...{W}")
    shutdown_flag.set()
    sys.exit(0)


# Attach signal handler for CTRL+C
signal.signal(signal.SIGINT, signal_handler)


def get_ip(domain):
    try:
        print(f"\n{Y}[~] IP lookup :{W} {domain}{W}\n")

        r = requests.get(
            f"http://ip-api.com/json/{domain}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        )
        res = r.json()
        countrycode = res["countryCode"]
        country = res["country"]
        region = res["region"]
        regionName = res["regionName"]
        city = res["city"]
        lat = res["lat"]
        lon = res["lon"]
        time_zone = res["timezone"]
        isp = res["isp"]
        query = res["query"]
        continent = res["continent"]
        continentcode = res["continentCode"]
        name = res["asname"]
        zip = res["zip"]
        proxy = res["proxy"]
        hosting = res["hosting"]
        mobile = res["mobile"]
        reverse = res["reverse"]
        district = res["district"]
        offset = res["offset"]
        currency = res["currency"]
        org = res["org"]
        status = res["status"]
        _as = res["as"]

        ip_info = (
            f"{G}[+] {C}IP: {W}{query}\n"
            # f"status: {status}\n"
            f"{G}[+] {C}continent: {W}{continent}\n"
            f"{G}[+] {C}continent code: {W}{continentcode}\n"
            f"{G}[+] {C}country: {W}{country}\n"
            f"{G}[+] {C}country code: {W}{countrycode}\n"
            f"{G}[+] {C}region name: {W}{regionName}\n"
            f"{G}[+] {C}region: {W}{region}\n"
            f"{G}[+] {C}city: {W}{city}\n"
            f"{G}[+] {C}district: {W}{district}\n"
            f"{G}[+] {C}zip: {W}{zip}\n"
            f"{G}[+] {C}timezone: {W}{time_zone}\n"
            f"{G}[+] {C}name: {W}{name}\n"
            f"{G}[+] {C}org: {W}{org}\n"
            f"{G}[+] {C}as: {W}{_as}\n"
            f"{G}[+] {C}isp: {W}{isp}\n"
            f"{G}[+] {C}reverse: {W}{reverse}\n"
            f"{G}[+] {C}offset: {W}{offset}\n"
            f"{G}[+] {C}currency: {W}{currency}\n"
            f"{G}[+] {C}proxy: {W}{proxy}\n"
            f"{G}[+] {C}hosting: {W}{hosting}\n"
            f"{G}[+] {C}mobile: {W}{mobile}\n"
            f"{G}[+] {C}latitude: {W}{lat}\n"
            f"{G}[+] {C}longitude: {W}{lon}"
        )

        print(ip_info)

    except Exception as e:
        print(e)


def headers(domain):
    target_host = f"https://{domain}"
    fetch_headers(url=target_host)


def perform_whois(domain):
    try:
        print(f"\n{Y}[~] Whois :{W}\n")
        domain = whois.whois(f"{domain}")

        """domain_info = (f"{G}\u2514\u27a4 {C}name: {W}{domain.name}\n"
                           f"{G}\u2514\u27a4 {C}tld: {W}{domain.tld}\n"
                           f"{G}\u2514\u27a4 {C}registrar: {W}{domain.registrar}\n"
                           f"{G}\u2514\u27a4 {C}registrant_country: {W}{domain.registrant_country}\n"
                           f"{G}\u2514\u27a4 {C}creation_date: {W}{domain.creation_date}\n"
                           f"{G}\u2514\u27a4 {C}expiration_date: {domain.expiration_date}\n"
                           f"{G}\u2514\u27a4 {C}last_updated: {W}{domain.last_updated}\n"
                           f"{G}\u2514\u27a4 {C}status: {W}{domain.status}\n"
                           f"{G}\u2514\u27a4 {C}statuses: {W}{domain.statuses}\n"
                           f"{G}\u2514\u27a4 {C}dnssec: {W}{domain.dnssec}\n"
                           f"{G}\u2514\u27a4 {C}registrant: {W}{domain.registrant}\n"
                           f"{G}\u2514\u27a4 {C}admin: {W}{domain.admin}\n"
                           f"{G}\u2514\u27a4 {C}owner: {W}{domain.owner}\n"
                           f"{G}\u2514\u27a4 {C}reseller: {W}{domain.reseller}\n"
                           f"{G}\u2514\u27a4 {C}emails: {W}{domain.emails}\n"
                           f"{G}\u2514\u27a4 {C}abuse_contact: {W}{domain.abuse_contact})")"""

        print(f"{G}{domain}")

    except Exception as e:
        print(e)


def check_ssl_certificate(domain):
    try:
        target_host = f"{domain}".strip()
        certificate_info = get_certificate_info(target_host)
        print_certificate_info(certificate_info)
    except Exception as e:
        print(e)


def run_dns_enumeration(domain):
    try:
        target_host = f"{domain}"
        dnsrec(domain=target_host)
    except Exception as e:
        print(e)


def run_reversedns(domain):
    try:
        print(f"\n{Y}[~] Reverse DNS :{W}\n")
        api = requests.get(
            f"https://api.hackertarget.com/reversedns/?q={domain}",
            timeout=3,
        ).text.split("\n")
        pprint(api)

    except Exception as e:
        print(e)


def run_dmarc_check(domain):
    try:
        dmarc_results = check_dmarc(domain)

        print(
            f"\n{Colors.YELLOW}[+] DMARC Check for {Colors.CYAN}{domain}{Colors.RESET}"
        )

        if dmarc_results.get("error"):
            print(f"{Colors.RED}[!] {dmarc_results['error']}{Colors.RESET}")
            return

        if not dmarc_results.get("exists", False):
            print(f"{Colors.YELLOW}[~] No DMARC record found{Colors.RESET}")
            return

        print(f"{Colors.GREEN}[ok] DMARC Record Found:{Colors.RESET}")
        print(
            f"{Colors.BLUE}Raw Record: {dmarc_results.get('record', 'N/A')}{Colors.RESET}"
        )

        # Display policy settings
        policies = dmarc_results.get("policy", [])
        if policies:
            print(f"\n{Colors.YELLOW}Policy Settings:{Colors.RESET}")
            for policy in policies:
                print(f"  {Colors.GREEN}-> {policy}{Colors.RESET}")

        # Display external links
        links = dmarc_results.get("links", [])
        if links:
            print(f"\n{Colors.YELLOW}External Links:{Colors.RESET}")
            for link in links:
                print(f"  {Colors.CYAN}-> {link}{Colors.RESET}")

        # Display reporting emails
        emails = dmarc_results.get("emails", [])
        if emails:
            print(f"\n{Colors.YELLOW}Reporting Emails:{Colors.RESET}")
            for email in emails:
                print(f"  {Colors.CYAN}-> {email}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Critical Error: {e}{Colors.RESET}")

    print("\n" + "=" * 50 + "\n")


def run_shareddns(domain):
    try:
        print(f"\n{Y}[~] Shared DNS :{W}\n")
        api = requests.get(
            f"https://api.hackertarget.com/findshareddns/?q={domain}",
            timeout=3,
        ).text.split("\n")
        pprint(api)

    except Exception as e:
        print(e)


def run_subdomain_enumeration(domain):
    try:
        setup_config()
        api_keys = get_api_keys()

        domain = f"{domain}"

        start_time = time.time()
        print(f"{COLORS['BLUE']}\n[*] Starting subdomain enumeration...")

        count = enumerate_subdomains(domain, api_keys)

        elapsed = time.time() - start_time
        print(f"{COLORS['WHITE']}\n[*] Total unique subdomains found: {count}")
        print(f"{COLORS['BLUE']}[!] Results saved to {domain}-subdomains.txt")
        print(f"{COLORS['YELLOW']}[*] Completed in {elapsed:.2f} seconds\n")

    except Exception as e:
        print(e)


def run_web_crawl(domain):
    try:
        target_host = f"https://{domain}"
        print(f"\n{Y}[~] Web Crawler :{W}\n")
        perform_web_recon(target_host)

    except Exception as e:
        print(e)


def check_robots_txt(domain):
    try:
        target_host = f"https://{domain}"
        print(f"\n{Y}[~] Robots & sitemap :{W}\n")
        check_website(target_host)

    except Exception as e:
        print(e)


def analyze_website_technologies(domain):
    try:
        website_url = f"https://{domain}"

        print(f"\n{Y}[~] Website build with :{W}\n")

        programming_languages, technologies, javascript_libraries, web_server = (
            analyze_website(website_url)
        )

        if programming_languages:
            print(
                f"{G}[+] {C}Detected programming languages:{W}",
                f", ".join(programming_languages),
            )
        else:
            print(f"{R}No programming language detected or an error occurred.")

        if technologies:
            print(f"\n{G}[+] {C}Website technologies:")
            for tech, details in technologies.items():
                print(f"{W}{tech}: {details}")
        else:
            print(f"{R}An error occurred while fetching technologies.")

        if javascript_libraries:
            print(f"\n{G}[+] {C}JavaScript libraries:")
            for library in javascript_libraries:
                print(f"{W}- " + library)
        else:
            print(f"{R}No JavaScript libraries detected.")

        print(f"\n{G}[+] {C}Web server:", f"{W}{web_server}")

    except Exception as e:
        print(e)


def wayback_links(domain):
    try:
        target_host = f"{domain}"
        print(f"\n{Y}[~] Wayback :{W}\n")
        fetch_wayback_links(target=target_host)
    except Exception as e:
        print(e)


def extract_social_links_and_emails(domain):
    try:
        target_host = f"https://{domain}"
        print(f"\n{Y}[~] Social media links :{W}\n")
        social_media_links, emails = extract_links_and_emails(target_host)

        if social_media_links:
            print("Social media links:")
            for link in social_media_links:
                print(link)
        else:
            print("No social media links found or an error occurred.")

        if emails:
            print("\nEmail addresses:")
            for email in emails:
                print(email)
        else:
            print("No email addresses found or an error occurred.")

    except Exception as e:
        print(e)


def run_directory_bruteforce(domain):
    try:
        # Define and set the variables with appropriate values
        target = f"https://{domain}"  # Replace with your actual target URL
        threads = 30  # Replace with the desired number of threads
        tout = 3  # Replace with the desired timeout value
        wdlist = os.path.join(base_dir, "wordlists/dirlist.txt")
        redir = False  # Replace with True or False depending on whether you want to allow redirects
        sslv = True  # Replace with True or False depending on your SSL verification preference
        dserv = "1.1.1.1"  # Replace with your DNS servers
        output = "output.txt"  # Replace with the path to your output file
        data = {}  # You can define and set any additional data as needed
        filext = (
            ""  # Replace with file extensions or leave empty if not needed (php, html)
        )

        # Call the functions from your_module here
        start_scan(
            target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext
        )

    except Exception as e:
        print(e)


def run_port_scan(domain):
    try:
        ps(ip=f"{domain}", threads=100)
    except Exception as e:
        print(e)


def find_admin_panels_on_domain(domain):
    try:
        sys.__stdout__.write(f"\n{Y}[~] Admin LogIn Panel:{W}\n\n")
        sys.__stdout__.write(f"\n{C}Scanning for Login Page. Please wait...\n")

        target_url = f"https://{domain}"
        paths_file = os.path.join(base_dir, "wordlists/paths.txt")
        num_threads = 30  # Use integer directly

        with open(paths_file, "r") as file:
            paths = file.read()

        result = find_admin_panels(target_url, paths, num_threads)

        # Print results after scanning completes
        sys.__stdout__.write("\nScan Completed!\n")
        for line in result:
            sys.__stdout__.write(line + "\n")

    except Exception as e:
        sys.__stdout__.write(f"{R}[!] Error: {e}{W}\n")


def write_to_file_and_stdout(domain):
    output_filename = f"{domain}-recon.txt"

    class Tee:
        def __init__(self, *files):
            self.files = files

        def write(self, obj):
            for file in self.files:
                if file.closed:
                    file = open(file.name, "a")  # Re-open file if it's closed
                file.write(obj)

        def flush(self):
            for file in self.files:
                if not file.closed:
                    file.flush()  # Ensure flushing works for open files

    with open(output_filename, "w") as output_file:
        tee = Tee(sys.stdout, output_file)
        sys.stdout = tee


def run_all(domain):
    print(f"Running all reconnaissance modules for {domain}")
    write_to_file_and_stdout(domain)
    get_ip(domain)
    headers(domain)
    perform_whois(domain)
    check_ssl_certificate(domain)
    run_dns_enumeration(domain)
    run_reversedns(domain)
    run_shareddns(domain)
    run_dmarc_check(domain)
    run_subdomain_enumeration(domain)
    run_web_crawl(domain)
    check_robots_txt(domain)
    analyze_website_technologies(domain)
    wayback_links(domain)
    extract_social_links_and_emails(domain)
    run_directory_bruteforce(domain)
    run_port_scan(domain)
    find_admin_panels_on_domain(domain)


# Utility Functions
def check_url_validity(url):
    try:
        response = requests.get(url)
        return response
    except requests.exceptions.RequestException:
        return None


def is_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def validate_target(host, is_ip_target, scheme, port):
    if is_ip_target:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            print(f"{R}[!] Invalid IP address: {host}")
            exit(1)
    else:
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            print(f"{R}[!] Could not resolve domain: {host}")
            exit(1)

    test_url = f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"
    try:
        response = requests.get(test_url, timeout=5)
        if response.status_code != 200:
            print(
                f"{Y}[!] Server responded with status code {R}{response.status_code}{W}"
            )
            print(f"{R}[!] Please enter a valid and reachable URL.")
            exit(1)
    except requests.exceptions.RequestException as e:
        print(f"{R}[!] Could not connect to {test_url}")
        print(f"{R}    Error: {e}")
        print(f"{R}[!] Please enter a valid and reachable URL.")
        exit(1)

    print(f"{G}[✓] Valid target. {Y}Proceeding with reconnaissance...{W}")


# Argument Handlers
def handle_args():
    parser = argparse.ArgumentParser(
        description=f"{R}Example:{G} omnisci3nt example.com -whois{Y}"
    )
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("-ip", action="store_true", help="Perform IP lookup")
    parser.add_argument("-headers", action="store_true", help="Fetch HTTP headers")
    parser.add_argument("-whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument(
        "-ssl", action="store_true", help="Retrieve SSL certificate information"
    )
    parser.add_argument("-dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("-reversedns", action="store_true", help="Show Reverse DNS")
    parser.add_argument("-shareddns", action="store_true", help="Show Shared DNS")
    parser.add_argument("-subdomains", action="store_true", help="Find subdomains")
    parser.add_argument("-dmarc", action="store_true", help="Check DMARC records")
    parser.add_argument("-crawl", action="store_true", help="Perform web crawling")
    parser.add_argument("-robots", action="store_true", help="Check robots.txt")
    parser.add_argument(
        "-tech", action="store_true", help="Analyze website technologies"
    )
    parser.add_argument(
        "-wayback", action="store_true", help="Fetch Wayback Machine links"
    )
    parser.add_argument(
        "-social", action="store_true", help="Extract social media links and emails"
    )
    parser.add_argument(
        "-dirscan", action="store_true", help="Perform directory scanning"
    )
    parser.add_argument("-portscan", action="store_true", help="Perform port scanning")
    parser.add_argument("-admin", action="store_true", help="Find admin panels")
    parser.add_argument("-all", action="store_true", help="Run all modules")
    return parser.parse_args()


# Main Execution
def main():
    print_program_banner()
    args = handle_args()

    target = args.target.strip()
    if "://" not in target:
        target = "http://" + target

    parsed_url = urlparse(target)
    host = parsed_url.hostname
    port = parsed_url.port
    scheme = parsed_url.scheme or "http"
    domain = host

    is_ip_target = is_ip(host)

    print(f"{C}Target: {W}{domain}\n")

    # Validate Target
    validate_target(host, is_ip_target, scheme, port)

    # Start Reconnaissance
    print_recon_started_banner()
    start_time = time.time()

    if args.all:
        run_all(domain)
    else:
        if args.ip:
            get_ip(domain)
        if args.headers:
            headers(domain)
        if args.whois:
            perform_whois(domain)
        if args.ssl:
            check_ssl_certificate(domain)
        if args.dns:
            run_dns_enumeration(domain)
        if args.reversedns:
            run_reversedns(domain)
        if args.shareddns:
            run_shareddns(domain)
        if args.dmarc:
            run_dmarc_check(domain)
        if args.subdomains:
            run_subdomain_enumeration(domain)
        if args.crawl:
            run_web_crawl(domain)
        if args.robots:
            check_robots_txt(domain)
        if args.tech:
            analyze_website_technologies(domain)
        if args.wayback:
            fetch_wayback_links(domain)
        if args.social:
            extract_social_links_and_emails(domain)
        if args.dirscan:
            run_directory_bruteforce(domain)
        if args.portscan:
            run_port_scan(domain)
        if args.admin:
            find_admin_panels_on_domain(domain)

    print_recon_completed_banner()

    end_time = time.time()
    elapsed_time = end_time - start_time

    print(f"{G}[+] {C}Date: {W}{formatted_date}")
    print(f"{G}[+] {C}Time taken: {W}{elapsed_time:.2f} seconds")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
