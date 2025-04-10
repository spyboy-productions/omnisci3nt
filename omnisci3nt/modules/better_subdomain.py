import requests
import re
import json
import time
import configparser
import os
from pathlib import Path

COLORS = {
    "RED": "\033[1;31m",
    "GREEN": "\033[1;32m",
    "YELLOW": "\033[1;33m",
    "BLUE": "\033[1;34m",
    "WHITE": "\033[1;37m",
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "application/json, text/html",
}

CONFIG_PATH = Path("config.ini")


def setup_config():
    """Create config file with template if it doesn't exist"""
    if not CONFIG_PATH.exists():
        config = configparser.ConfigParser()
        config["API"] = {
            "# Get free API keys below": "",
            "# VirusTotal": "https://www.virustotal.com/gui/join-us",
            "# SecurityTrails": "https://securitytrails.com/app/signup",
            "virustotal": "",
            "securitytrails": "",
        }
        with open(CONFIG_PATH, "w") as f:
            config.write(f)
        print(
            f"{COLORS['YELLOW']}[i] Created config.ini - Add your Free API keys to enable premium sources"
        )


def get_api_keys():
    """Read API keys from config file"""
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    return {
        "virustotal": config["API"].get("virustotal", "").strip(),
        "securitytrails": config["API"].get("securitytrails", "").strip(),
    }


def print_subdomains(source, subdomains):
    if subdomains:
        print(f"{COLORS['GREEN']}\n[+] {source} found:")
        for sub in sorted(subdomains):
            print(f"  {COLORS['GREEN']}{sub}")
    else:
        print(f"{COLORS['RED']}\n[-] {source} found nothing")


def fetch_url(url, regex_pattern, domain):
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        return set(re.findall(regex_pattern, response.text))
    except Exception as e:
        print(f"{COLORS['RED']}[-] Error fetching {url}: {str(e)}")
        return set()


def enumerate_subdomains(domain, api_keys):
    all_subdomains = set()

    # CRT.SH
    print(f"{COLORS['BLUE']}\n[i] Checking crt.sh...")
    crt_subs = fetch_url(
        f"https://crt.sh/?q={domain}", rf"(?:[\w-]+\.)+{re.escape(domain)}", domain
    )
    print_subdomains("crt.sh", crt_subs)
    all_subdomains.update(crt_subs)

    # RapidDNS
    print(f"{COLORS['BLUE']}\n[i] Checking RapidDNS...")
    rapiddns_subs = fetch_url(
        f"https://rapiddns.io/subdomain/{domain}",
        rf"<td>((?:[\w-]+\.)+{re.escape(domain)})</td>",
        domain,
    )
    print_subdomains("RapidDNS", rapiddns_subs)
    all_subdomains.update(rapiddns_subs)

    # AnubisDB
    print(f"{COLORS['BLUE']}\n[i] Checking AnubisDB...")
    try:
        response = requests.get(
            f"https://jldc.me/anubis/subdomains/{domain}", headers=HEADERS, timeout=15
        )
        anubis_subs = set(json.loads(response.text))
        print_subdomains("AnubisDB", anubis_subs)
        all_subdomains.update(anubis_subs)
    except Exception as e:
        print(f"{COLORS['RED']}[-] AnubisDB error: {str(e)}")

    # VirusTotal
    if api_keys["virustotal"]:
        print(f"{COLORS['BLUE']}\n[i] Checking VirusTotal...")
        try:
            headers = {"x-apikey": api_keys["virustotal"]}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100",
                headers=headers,
                timeout=15,
            )
            vt_subs = set([item["id"] for item in response.json()["data"]])
            print_subdomains("VirusTotal", vt_subs)
            all_subdomains.update(vt_subs)
        except Exception as e:
            print(f"{COLORS['RED']}[-] VirusTotal error: {str(e)}")
    else:
        print(
            f"{COLORS['YELLOW']}\n[i] VirusTotal skipped - Add API key to config.ini to enable"
        )

    # SecurityTrails
    if api_keys["securitytrails"]:
        print(f"{COLORS['BLUE']}\n[i] Checking SecurityTrails...")
        try:
            headers = {"APIKEY": api_keys["securitytrails"]}
            response = requests.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers=headers,
                timeout=15,
            )
            st_subs = set([f"{sub}.{domain}" for sub in response.json()["subdomains"]])
            print_subdomains("SecurityTrails", st_subs)
            all_subdomains.update(st_subs)
        except Exception as e:
            print(f"{COLORS['RED']}[-] SecurityTrails error: {str(e)}")
    else:
        print(
            f"{COLORS['YELLOW']}\n[i] SecurityTrails skipped - Add API key to config.ini to enable"
        )

    # Save results
    filename = f"{domain}-subdomains.txt"
    with open(filename, "w") as f:
        f.write("\n".join(sorted(all_subdomains)))

    return len(all_subdomains)


if __name__ == "__main__":
    setup_config()
    api_keys = get_api_keys()

    domain = input(f"{COLORS['WHITE']}\n[!] Enter domain to enumerate: ")
    start_time = time.time()
    print(f"{COLORS['BLUE']}\n[*] Starting enumeration...")
    count = enumerate_subdomains(domain, api_keys)
    elapsed = time.time() - start_time
    print(f"{COLORS['WHITE']}\n[*] Total unique subdomains found: {count}")
    print(f"{COLORS['BLUE']}[!] Results saved to {domain}-subdomains.txt")
    print(f"{COLORS['YELLOW']}[*] Completed in {elapsed:.2f} seconds\n")
