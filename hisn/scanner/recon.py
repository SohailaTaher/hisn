"""
HISN — Domain Reconnaissance Module
====================================
Performs PASSIVE reconnaissance on a target domain:
  - WHOIS lookup (who registered it, when, where)
  - DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - Subdomain enumeration via Subfinder

This is the first step of any external security assessment.
Everything here is PASSIVE — we never send packets directly
to the target. We only query public sources (WHOIS servers,
DNS servers, certificate logs).

Usage:
    python -m hisn.scanner.recon <domain>

Example:
    python -m hisn.scanner.recon scanme.nmap.org

Author: Sohaila Taher Shaker
License: MIT
"""

import sys
import subprocess
from datetime import datetime

import dns.resolver
import whois
import tldextract
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from hisn.scanner.dns_utils import query_dns


# Rich console object handles all our pretty colored output
console = Console()


# ---------------------------------------------------------------------------
# Helper: validate the domain looks legit
# ---------------------------------------------------------------------------
def validate_domain(domain: str) -> bool:
    """Return True if the input looks like a real domain (has a TLD)."""
    extracted = tldextract.extract(domain)
    return bool(extracted.domain and extracted.suffix)


# ---------------------------------------------------------------------------
# WHOIS lookup
# ---------------------------------------------------------------------------
def get_whois_info(domain: str) -> dict:
    """
    Query domain registration via RDAP (HTTPS replacement for port 43 WHOIS).
    RDAP is the ICANN-standard modern replacement for WHOIS.
    rdap.org is a free meta-service that routes to the correct RDAP server per TLD.
    """
    def to_list(value):
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]

    try:
        import requests
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=15,
            headers={"Accept": "application/rdap+json"},
        )
        if response.status_code != 200:
            return {"Error": f"RDAP returned status {response.status_code}"}

        data = response.json()

        # --- Registrar (lives inside entities[].vcardArray) ---
        registrar = "Unknown"
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcards = entity.get("vcardArray", [None, []])[1]
                for vcard in vcards:
                    if len(vcard) >= 4 and vcard[0] == "fn":
                        registrar = vcard[3]
                        break
                break

        # --- Dates (from events array) ---
        creation_date = "Unknown"
        expiration_date = "Unknown"
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration":
                creation_date = date
            elif action == "expiration":
                expiration_date = date

        # --- Nameservers ---
        name_servers = [
            ns.get("ldhName", "").lower()
            for ns in data.get("nameservers", [])
            if ns.get("ldhName")
        ]

        # --- Status codes ---
        statuses = to_list(data.get("status"))

        return {
            "Registrar": registrar,
            "Creation Date": creation_date,
            "Expiration Date": expiration_date,
            "Name Servers": ", ".join(name_servers) if name_servers else "Unknown",
            "Status": "\n".join(statuses) if statuses else "Unknown",
        }
    except Exception as e:
        return {"Error": str(e)}

# ---------------------------------------------------------------------------
# DNS record lookup
# ---------------------------------------------------------------------------
def get_dns_records(domain: str) -> dict:
    """
    Get DNS records of all common types via DoH.
      A     = IPv4 address
      AAAA  = IPv6 address
      MX    = Mail server
      NS    = Name server
      TXT   = Free-form text (SPF/DKIM/DMARC live here!)
      CNAME = Alias
      SOA   = Start of Authority
    """
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for record_type in record_types:
        records[record_type] = query_dns(domain, record_type)
    return records


# ---------------------------------------------------------------------------
# Subdomain enumeration via Subfinder
# ---------------------------------------------------------------------------
def enumerate_subdomains(domain: str) -> list:
    """
    Run the Subfinder CLI tool and collect its output.

    Subfinder queries dozens of public sources (certificate
    transparency logs, search engines, DNS aggregators) to find
    subdomains. Every subdomain found = another door an attacker
    could try to pick.
    """
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        subdomains = result.stdout.strip().split("\n")
        return sorted([s for s in subdomains if s])
    except subprocess.TimeoutExpired:
        return ["[TIMEOUT — subfinder took longer than 2 minutes]"]
    except FileNotFoundError:
        return ["[ERROR — subfinder not installed or not in PATH]"]
    except Exception as e:
        return [f"[ERROR — {str(e)}]"]


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
def display_banner():
    """Print the HISN ASCII banner."""
    banner = """
[bold cyan]██╗  ██╗██╗███████╗███╗   ██╗
██║  ██║██║██╔════╝████╗  ██║
███████║██║███████╗██╔██╗ ██║
██╔══██║██║╚════██║██║╚██╗██║
██║  ██║██║███████║██║ ╚████║
╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝[/bold cyan]
[yellow]External Security Posture Platform[/yellow]
[dim]Reconnaissance Module · v0.1.0[/dim]
"""
    console.print(banner)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def run_recon(domain: str):
    """Run the full reconnaissance pipeline and print the report."""
    display_banner()

    console.print(f"🎯  Target: [bold green]{domain}[/bold green]")
    console.print(f"📅  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    if not validate_domain(domain):
        console.print(f"[bold red]❌  Invalid domain: {domain}[/bold red]")
        sys.exit(1)

    # --- WHOIS ---
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("Querying WHOIS registries...", total=None)
        whois_info = get_whois_info(domain)

    whois_table = Table(title="📜  WHOIS Information", title_style="bold cyan", show_lines=True)
    whois_table.add_column("Field", style="bold yellow")
    whois_table.add_column("Value", style="white")
    for key, value in whois_info.items():
        whois_table.add_row(key, str(value))
    console.print(whois_table)

    # --- DNS ---
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("Resolving DNS records...", total=None)
        dns_records = get_dns_records(domain)

    dns_table = Table(title="🌐  DNS Records", title_style="bold cyan", show_lines=True)
    dns_table.add_column("Type", style="bold yellow")
    dns_table.add_column("Value(s)", style="white")
    for rtype, records in dns_records.items():
        if records:
            dns_table.add_row(rtype, "\n".join(records))
        else:
            dns_table.add_row(rtype, "[dim]None found[/dim]")
    console.print(dns_table)

    # --- Subdomains ---
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("Enumerating subdomains (this can take 30–90 seconds)...", total=None)
        subdomains = enumerate_subdomains(domain)

    sub_table = Table(
        title=f"🔍  Subdomains Discovered ({len(subdomains)})",
        title_style="bold cyan",
    )
    sub_table.add_column("Subdomain", style="green")
    if subdomains:
        for sub in subdomains:
            sub_table.add_row(sub)
    else:
        sub_table.add_row("[dim]No subdomains discovered[/dim]")
    console.print(sub_table)

    console.print("\n[bold green]✅  Reconnaissance complete![/bold green]\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python -m hisn.scanner.recon <domain>")
        console.print("[bold yellow]Example:[/bold yellow] python -m hisn.scanner.recon scanme.nmap.org")
        sys.exit(1)

    target = sys.argv[1]
    run_recon(target)