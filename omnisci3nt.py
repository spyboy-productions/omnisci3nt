#!/usr/bin/env python3
#omnisci3nt: Unveiling the Hidden Layers of the Web – A Comprehensive Web Reconnaissance Tool
import re
import sys
import requests
import whois #python-whois
import asyncio
import time
from datetime import datetime

from sl import get_certificate_info, print_certificate_info
from header import fetch_headers
from dns_enumeration import dnsrec
from dmarc_record import fetch_dmarc_links
from web_carwl import perform_web_recon
from robo_checker import check_website
from buildwith import analyze_website
from wayback import fetch_wayback_links
from social_media import extract_links_and_emails
from sdomain import find_subdomains

current_date = datetime.now().date()
formatted_date = current_date.strftime("%Y-%m-%d")

twitter_url = 'https://spyboy.in/twitter'
discord = 'https://spyboy.in/Discord'
website = 'https://spyboy.in/'
blog = 'https://spyboy.blog/'
github = 'https://github.com/spyboy-productions/omnisci3nt'

VERSION = '1.0.1'

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

banner = r'''                                               
                      .__              .__________         __   
  ____   _____   ____ |__| ______ ____ |__\_____  \  _____/  |_ 
 /  _ \ /     \ /    \|  |/  ___// ___\|  | _(__  < /    \   __\
(  <_> )  Y Y  \   |  \  |\___ \\  \___|  |/       \   |  \  |  
 \____/|__|_|  /___|  /__/____  >\___  >__/______  /___|  /__|  
             \/     \/        \/     \/          \/     \/ 
    Unveiling the Hidden Layers of the Web.     

'''

def print_banners():
    """
    prints the program banners
    """
    print(f'{R}{banner}{W}\n')
    print(f'{G}[+] {Y}Version      : {W}{VERSION}')
    print(f'{G}[+] {Y}Created By   : {W}Spyboy')
    print(f'{G} ╰➤ {Y}Twitter      : {W}{twitter_url}')
    print(f'{G} ╰➤ {Y}Discord      : {W}{discord}')
    print(f'{G} ╰➤ {Y}Website      : {W}{website}')
    print(f'{G} ╰➤ {Y}Blog         : {W}{blog}\n')

######
# List of ports to scan (top 1000 ports)
port_list = list(range(1, 1001))

async def sock_conn(ip, port, result):
    try:
        connector = asyncio.open_connection(ip, port)
        await asyncio.wait_for(connector, timeout=1)
        result['ports'].append(port)
        #print(f'\x1b[K{G}[+] {C}{port}{W}')
    except (TimeoutError, ConnectionRefusedError):
        pass

async def run(ip, threads):
    result = {'ports': []}
    tasks = [sock_conn(ip, port, result) for port in port_list]

    await asyncio.gather(*tasks, return_exceptions=True)  # Added return_exceptions=True

    print(f"\n{G}[+] {C}Total Port Scanned:{W} 1001")

    print(f'\n{Y}[!] {C}Scanning completed! Open ports:{W} {result["ports"]}\n')

async def scan_ports(ip, threads=100):
    print(f'\n{Y}[!] Starting Port Scan...{W}\n')
    #print(f'{G}[+] {C}Scanning Top 1000 Ports With {threads} Threads...{W}\n')

    loop = asyncio.get_event_loop()
    try:
        await run(ip, threads)
    except asyncio.TimeoutError:
        print(f'{R}[!] {C}Connection timeout.{W}\n')

################
print_banners()

input_text = input("Enter Domain or URL: ")
if input_text.startswith("http://") or input_text.startswith("https://"):
    match = re.search(r'(https?://)?([A-Za-z_0-9.-]+).*', input_text)
    if match:
        link = match.group(2)
    else:
        print("Invalid URL format.")
        exit(1)
else:
    link = input_text

output_filename = f"recon({link}).text"
with open(output_filename, "w") as output_file:
    class Tee:
        def __init__(self, *files):
            self.files = files

        def write(self, obj):
            for f in self.files:
                f.write(obj)
                f.flush()  # Make sure it's flushed immediately

    tee = Tee(sys.stdout, output_file)

    sys.stdout = tee

    banner2 = r'''
    |￣￣￣￣￣￣￣￣￣￣￣￣￣|
         Recon Started 
    |＿＿＿＿＿＿＿＿＿＿＿＿＿|
          \(•◡•)/ 
           \   / 
            ——— 
           |   |
           |   |
    '''
    #print(f"\n{R}Starting the Recon\n")
    print(f"{G}{banner2}")
    start_time = time.time()

    ################

    ### IP Lookup
    try:
        print(f'\n{Y}[!] IP lookup :{W}\n')

        r = requests.get(
            f"http://ip-api.com/json/{link}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
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
        ass = res["as"]

        ip_info = (f"{G}[+] {C}IP: {W}{query}\n"
                   # f"status: {status}\n"
                   f"{G}[+] {C}continent: {W}{continent}\n"
                   f"{G}[+] {C}continent code: {W}{continentcode}\n"
                   f"{G}[+] {C}country: {W}{country}\n"
                   f"{G}[+] {C}country code: {W}{countrycode}\n"
                   f"{G}[+] {C}region name: {W}{regionName}"
                   f"{G}[+] {C}region: {W}{region}\n"
                   f"{G}[+] {C}city: {W}{city}\n"
                   f"{G}[+] {C}district: {W}{district}\n"
                   f"{G}[+] {C}zip: {W}{zip}\n"
                   f"{G}[+] {C}timezone: {time_zone}"
                   f"{G}[+] {C}name: {W}{name}\n"
                   f"{G}[+] {C}org: {W}{org}\n"
                   f"{G}[+] {C}ase: {W}{ass}"
                   f"{G}[+] {C}isp: {W}{isp}\n"
                   f"{G}[+] {C}reverse: {W}{reverse}"
                   f"{G}[+] {C}offset: {W}{offset}\n"
                   f"{G}[+] {C}currency: {W}{currency}\n"
                   f"{G}[+] {C}proxy: {W}{proxy}\n"
                   f"{G}[+] {C}hosting: {W}{hosting}\n"
                   f"{G}[+] {C}mobile: {W}{mobile}"
                   f"{G}[+] {C}latitude: {W}{lat}\n"
                   f"{G}[+] {C}longitude: {W}{lon}")

        print(ip_info)

    except Exception as e:
        print(e)

    ### Header
    if __name__ == "__main__":
        target_host = f"https://{link}"
        fetch_headers(url=target_host)

    ### whois lookup
        try:
            print(f'\n{Y}[!] Whois :{W}\n')

            domain = whois.whois(f"{link}")

            domain_info = (f"{G}[+] {C}name: {W}{domain.name}\n"
                           f"{G}[+] {C}tld: {W}{domain.tld}\n"
                           f"{G}[+] {C}registrar: {W}{domain.registrar}\n"
                           f"{G}[+] {C}registrant_country: {W}{domain.registrant_country}\n"
                           f"{G}[+] {C}creation_date: {W}{domain.creation_date}\n"
                           f"{G}[+] {C}expiration_date: {domain.expiration_date}\n"
                           f"{G}[+] {C}last_updated: {W}{domain.last_updated}\n"
                           f"{G}[+] {C}status: {W}{domain.status}\n"
                           f"{G}[+] {C}statuses: {W}{domain.statuses}\n"
                           f"{G}[+] {C}dnssec: {W}{domain.dnssec}\n"
                           f"{G}[+] {C}registrant: {W}{domain.registrant}\n"
                           f"{G}[+] {C}admin: {W}{domain.admin}\n"
                           f"{G}[+] {C}owner: {W}{domain.owner}\n"
                           f"{G}[+] {C}reseller: {W}{domain.reseller}\n"
                           f"{G}[+] {C}emails: {W}{domain.emails}\n"
                           f"{G}[+] {C}abuse_contact: {W}{domain.abuse_contact})")

            print(domain_info)

        except Exception as e:
            print(e)

    ### SSL certificate checker
    if __name__ == "__main__":
        try:
            target_host = f"{link}"
            certificate_info = get_certificate_info(target_host)
            print_certificate_info(certificate_info)
        except Exception as e:
            print(e)
          

    ### DNS enumeration
    if __name__ == "__main__":
        try:

            target_host = f"{link}"
            dnsrec(domain=target_host)
        except Exception as e:
            print(e)

    ### Shared DNS
        try:
            print(f'\n{Y}[!] Shared DNS :{W}\n')
            api = requests.get(f'https://api.hackertarget.com/findshareddns/?q={link}', timeout=3).text.split('\n')
            print(api)

        except Exception as e:
            print(e)

    ### Reverse DNS
        try:
            print(f'\n{Y}[!] Reverse DNS :{W}\n')
            api = requests.get(f'https://api.hackertarget.com/reversedns/?q={link}', timeout=3).text.split('\n')
            print(api)

        except Exception as e:
            print(e)

    ### Subdomain Enumeration
    if __name__ == "__main__":
        try:
            target_host = f"{link}"
            print(f"\n{C}Scanning for subdomains. Please wait...")
            find_subdomains(domain=target_host, filename='wordlist2.txt')
        except Exception as e:
            print(e)

    ### Port scan
    if __name__ == "__main__":
        try:

            target_host = f"{link}"
            asyncio.run(scan_ports(target_host, threads=100))  # Await the coroutine using asyncio.run()

        except Exception as e:
            print(e)

    ### Web Crawler
    if __name__ == "__main__":
        try:

            target_host = f"https://{link}"
            print(f'\n{Y}[!] Web Crawler :{W}\n')
            perform_web_recon(target_host)

        except Exception as e:
            print(e)

    ### Robots & sitemap Crawler
    if __name__ == "__main__":
        try:

            target_host = f"https://{link}"
            print(f'\n{Y}[!] Robots & sitemap :{W}\n')
            check_website(target_host)

        except Exception as e:
            print(e)

    ### website build with
    if __name__ == "__main__":
        try:

            website_url = f"https://{link}"

            print(f'\n{Y}[!] Website build with :{W}\n')

            programming_languages, technologies, javascript_libraries, web_server = analyze_website(website_url)

            if programming_languages:
                print(f"{G}[+] {C}Detected programming languages:{W}", f", ".join(programming_languages))
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


    ### Wayback
    if __name__ == "__main__":
        try:

            target_host = f"{link}"
            print(f'\n{Y}[!] Wayback :{W}\n')
            fetch_wayback_links(target=target_host)

        except Exception as e:
            print(e)

    ### DMARC Record
    if __name__ == "__main__":
        try:

            target_host = f"{link}"
            fetch_dmarc_links(domain=target_host)

        except Exception as e:
            print(e)

    ### Social media links
    if __name__ == "__main__":
        try:

            target_host = f"https://{link}"
            print(f'\n{Y}[!] Social media links :{W}\n')
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

    ### Completed!!

    end_time = time.time()
    elapsed_time = end_time - start_time

    banner3 = r'''
    ￣￣￣￣￣￣￣￣￣￣￣￣￣￣
       Recon completed                        
    ＿＿＿＿＿＿＿＿＿＿＿＿＿＿ 
    (\__/) || 
    (•ㅅ•) || 
    / 　 づ

    '''
    print(f"{R}{banner3}")
    #print(f"\n{R}Recon completed\n")
    print(f"{G}[+] {C}Date: {W}{formatted_date}")
    print(f"{G}[+] {C}Time taken: {W}{elapsed_time:.2f} seconds")
    sys.stdout = sys.__stdout__  # Restore standard output

print(f"{G}[+] {C}Output saved to '{output_filename}'")
