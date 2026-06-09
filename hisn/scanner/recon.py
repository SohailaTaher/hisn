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
    Query WHOIS registries to find out:
      - Who registered the domain
      - When it was created and expires
      - Which nameservers it uses

    Defensive: the python-whois library returns some fields as a string
    OR a list depending on the registrar — we normalize both.
    """
    def to_list(value):
        """Force a value to be a list, whether it starts as None, str, or list."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]

    try:
        w = whois.whois(domain)
        return {
            "Registrar": w.registrar or "Unknown",
            "Creation Date": str(w.creation_date) if w.creation_date else "Unknown",
            "Expiration Date": str(w.expiration_date) if w.expiration_date else "Unknown",
            "Name Servers": ", ".join(to_list(w.name_servers)) or "Unknown",
            "Status": "\n".join(to_list(w.status)) or "Unknown",
        }
    except Exception as e:
        return {"Error": str(e)}

# ---------------------------------------------------------------------------
# DNS record lookup
# ---------------------------------------------------------------------------
def get_dns_records(domain: str) -> dict:
    """
    Query DNS for all common record types.
      A     = IPv4 address
      AAAA  = IPv6 address
      MX    = Mail server
      NS    = Name server
      TXT   = Free-form text (often holds SPF/DKIM/DMARC = email security!)
      CNAME = Alias to another domain
      SOA   = Start of Authority (zone administrative info)

    TXT records are especially valuable — they reveal whether the
    domain is protected against email spoofing.
    """
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            records[record_type] = []
        except dns.resolver.NXDOMAIN:
            records[record_type] = ["[DOMAIN NOT FOUND]"]
        except Exception:
            records[record_type] = []

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