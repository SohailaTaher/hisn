"""
HISN — DNS Utilities
====================
DNS queries via JSON DoH (DNS-over-HTTPS, JSON format).

Why this approach:
- Standard DNS (port 53) is often blocked or filtered (ISPs, schools, corp networks)
- Wire-format DoH on port 443 is also blocked by DPI on some networks
- JSON DoH uses plain HTTPS GET requests that look like normal API traffic,
  so it bypasses almost all DNS filtering

Cloudflare is tried first (works through Egyptian ISP filtering).
Google as fallback (works on most other networks).
"""

import re
import requests

DOH_ENDPOINTS = [
    {
        "url": "https://cloudflare-dns.com/dns-query",
        "headers": {"Accept": "application/dns-json"},
    },
    {
        "url": "https://dns.google/resolve",
        "headers": {},
    },
]


def _parse_txt(value: str) -> str:
    """
    JSON DoH returns TXT data with syntactic quotes:
        '"v=spf1 -all"'              → 'v=spf1 -all'
        '"part1" "part2"'            → 'part1part2'   (long TXT records)
    """
    parts = re.findall(r'"([^"]*)"', value)
    return "".join(parts) if parts else value.strip('"')


def query_dns(domain: str, record_type: str) -> list:
    """
    Query DNS via JSON DoH.

    Args:
        domain:      Domain to query (e.g., "gmail.com")
        record_type: DNS record type (e.g., "TXT", "A", "AAAA", "MX", "NS")

    Returns:
        List of records as strings, or [] if all endpoints fail
        or the domain has no records of that type.
    """
    rtype = record_type.upper()

    for endpoint in DOH_ENDPOINTS:
        try:
            response = requests.get(
                endpoint["url"],
                params={"name": domain, "type": rtype},
                headers=endpoint["headers"],
                timeout=10,
            )
            if response.status_code != 200:
                continue

            data = response.json()

            # Status 0 = no error. Anything else = NXDOMAIN, SERVFAIL, etc.
            if data.get("Status", -1) != 0:
                return []

            results = []
            for answer in data.get("Answer", []):
                value = answer.get("data", "")
                if rtype == "TXT":
                    value = _parse_txt(value)
                results.append(value)
            return results

        except (requests.RequestException, ValueError):
            continue  # Try the next endpoint

    return []