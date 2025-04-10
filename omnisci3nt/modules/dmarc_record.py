# dmarc_checker.py
import dns.resolver
import re
from typing import Optional, Dict


class Colors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    RESET = "\033[0m"


def get_dmarc_record(domain: str, timeout: int = 10) -> Optional[str]:
    """Query and return DMARC record for a domain."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=timeout)
        for record in answers:
            record_str = " ".join([s.decode() for s in record.strings])
            if "v=DMARC1" in record_str:
                return record_str
        return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except dns.exception.DNSException as e:
        raise RuntimeError(f"{Colors.RED}DNS Error: {e}{Colors.RESET}") from e


def parse_dmarc(record: str) -> Dict[str, list]:
    """Parse DMARC record into structured data."""
    dmarc_data = {"policy": [], "links": [], "emails": [], "raw": record}

    # Policy tags to extract
    policy_tags = ["v", "p", "sp", "pct", "fo", "rf", "ri"]
    for tag in policy_tags:
        match = re.search(rf"{tag}=([^;]+)", record, re.IGNORECASE)
        if match:
            dmarc_data["policy"].append(f"{tag.upper()}: {match.group(1)}")

    # URI extraction with improved pattern
    uri_pattern = r"(?:rua|ruf)=([^,]+)"
    uris = re.findall(uri_pattern, record, re.IGNORECASE)

    for uri in uris:
        uri = uri.strip()
        if uri.startswith("mailto:"):
            dmarc_data["emails"].append(
                uri[7:].split("!")[0]
            )  # Handle email formatting
        else:
            dmarc_data["links"].append(uri)

    return dmarc_data


def check_dmarc(domain: str) -> Dict:
    """Main function to check DMARC and return structured results."""
    result = {
        "domain": domain,
        "exists": False,
        "record": None,
        "policy": [],
        "links": [],
        "emails": [],
        "error": None,
    }

    try:
        record = get_dmarc_record(domain)
        if not record:
            result["error"] = "No DMARC record found"
            return result

        parsed = parse_dmarc(record)
        result.update(
            {
                "exists": True,
                "record": parsed["raw"],
                "policy": parsed["policy"],
                "links": parsed["links"],
                "emails": parsed["emails"],
            }
        )

    except Exception as e:
        result["error"] = str(e)

    return result
