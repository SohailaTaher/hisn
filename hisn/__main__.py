"""
HISN — Unified Security Audit
==============================
The main entry point. Combines all four scanner modules into a
single comprehensive security audit with one overall HISN grade.

Usage:
    python -m hisn scan <domain>

Example:
    python -m hisn scan bue.edu.eg
"""

import sys
import time
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from hisn.scanner.email_security import (
    check_spf, check_dmarc, check_dkim,
    calculate_overall as email_calculate_overall,
)
from hisn.scanner.port_scanner import (
    run_nmap_scan, parse_nmap_output, assess_risk,
)
from hisn.scanner.tls_audit import (
    fetch_certificate_info, assess_tls,
)
from hisn.scanner.recon import (
    get_whois_info, enumerate_subdomains,
)
from hisn.scanner.dns_utils import query_dns

console = Console()


# Weight each module's contribution to the overall HISN grade
MODULE_WEIGHTS = {
    "email_security": 0.35,
    "port_exposure":  0.30,
    "tls_ssl":        0.35,
}


# --------------------------------------------------------------------------
def display_banner():
    banner = """
[bold cyan]██╗  ██╗██╗███████╗███╗   ██╗
██║  ██║██║██╔════╝████╗  ██║
███████║██║███████╗██╔██╗ ██║
██╔══██║██║╚════██║██║╚██╗██║
██║  ██║██║███████║██║ ╚████║
╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝[/bold cyan]
[yellow]External Security Posture Platform[/yellow]
[bold white]Full Security Audit · v0.1.0[/bold white]
"""
    console.print(banner)


def grade_overall(score):
    """Map a numeric score to a letter grade + verdict + display color."""
    if score >= 90:
        return "A", "Excellent overall security posture — well-defended attack surface", "bold green"
    if score >= 75:
        return "B", "Good security posture with minor improvements possible", "green"
    if score >= 60:
        return "C", "Fair security posture — important fixes needed", "yellow"
    if score >= 40:
        return "D", "Poor security posture — significant weaknesses exposed", "bright_red"
    return "F", "Failing security posture — immediate action required", "bold red"


# --------------------------------------------------------------------------
def run_full_audit(domain: str):
    display_banner()
    start_time = time.time()

    console.print(f"🎯  Target: [bold green]{domain}[/bold green]")
    console.print(f"📅  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(
        "[dim]This runs all four HISN modules — typically 60–120 seconds total.[/dim]\n"
    )

    # ────────────── Phase 1: Reconnaissance ──────────────
    console.print("[bold cyan]━━━ Phase 1/4: Reconnaissance ━━━[/bold cyan]")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("WHOIS + subdomain discovery...", total=None)
        whois_info = get_whois_info(domain)
        subdomains = enumerate_subdomains(domain)
        ip_records = (
            query_dns(domain, "A")
            or query_dns(f"www.{domain}", "A")
            or ["Unknown"]
        )

    # ────────────── Phase 2: Email Security ──────────────
    console.print("[bold cyan]━━━ Phase 2/4: Email Security Audit ━━━[/bold cyan]")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("SPF + DMARC + DKIM checks...", total=None)
        spf = check_spf(domain)
        dmarc = check_dmarc(domain)
        dkim = check_dkim(domain)
        email_overall = email_calculate_overall(spf, dmarc, dkim)

    # ────────────── Phase 3: Port Exposure ──────────────
    console.print("[bold cyan]━━━ Phase 3/4: Port Exposure Scan ━━━[/bold cyan]")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("Nmap scan of common ports...", total=None)
        raw_nmap = run_nmap_scan(domain)
        open_ports = parse_nmap_output(raw_nmap) if raw_nmap else []
        port_assessment = assess_risk(open_ports)

    # ────────────── Phase 4: TLS / SSL ──────────────
    console.print("[bold cyan]━━━ Phase 4/4: TLS / SSL Audit ━━━[/bold cyan]")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("Certificate + TLS configuration analysis...", total=None)
        cert_info = fetch_certificate_info(domain)
        tls_assessment = assess_tls(cert_info, domain)

    duration = time.time() - start_time
    console.print(f"\n[dim]All four phases complete in {duration:.1f}s[/dim]\n")

    # ────────────── Reconnaissance Summary ──────────────
    t = Table(title="🔍  Reconnaissance Summary", title_style="bold cyan", show_lines=True)
    t.add_column("Field", style="bold yellow")
    t.add_column("Value", style="white")
    t.add_row("IP Address", str(ip_records[0]))
    t.add_row("Registrar", str(whois_info.get("Registrar", "Unknown")))
    t.add_row("Registered Since", str(whois_info.get("Creation Date", "Unknown")))
    t.add_row("Expires", str(whois_info.get("Expiration Date", "Unknown")))
    t.add_row("Subdomains Discovered", str(len(subdomains)))
    console.print(t)

    # ────────────── Module Scores ──────────────
    t = Table(title="📊  Module Scores", title_style="bold cyan", show_lines=True)
    t.add_column("Module", style="bold yellow")
    t.add_column("Score", justify="center")
    t.add_column("Grade", justify="center")
    t.add_column("Weight", style="dim", justify="center")
    t.add_row("📧  Email Security", f"{email_overall['score']}/100", email_overall["grade"], "35%")
    t.add_row("🔍  Port Exposure",  f"{port_assessment['score']}/100", port_assessment["grade"], "30%")
    t.add_row("🔐  TLS / SSL",      f"{tls_assessment['score']}/100",  tls_assessment["grade"],  "35%")
    console.print(t)

    # ────────────── Overall HISN Grade ──────────────
    overall_score = round(
        email_overall["score"]    * MODULE_WEIGHTS["email_security"]
        + port_assessment["score"] * MODULE_WEIGHTS["port_exposure"]
        + tls_assessment["score"]  * MODULE_WEIGHTS["tls_ssl"]
    )
    grade, verdict, color = grade_overall(overall_score)

    console.print()
    console.print(Panel(
        f"[{color}]Score: {overall_score}/100   ·   Grade: {grade}[/{color}]\n\n{verdict}",
        title="🎯  Overall HISN Security Score",
        title_align="left",
        border_style=color,
        padding=(1, 2),
    ))

    # ────────────── Consolidated Issues ──────────────
    all_issues = []
    all_issues.extend(spf.get("issues", []))
    all_issues.extend(dmarc.get("issues", []))
    all_issues.extend(dkim.get("issues", []))
    for r in port_assessment.get("risky", []):
        all_issues.append(f"Port {r['port']} ({r['service']}) — {r['severity']}: {r['reason']}")
    all_issues.extend(tls_assessment.get("issues", []))

    if all_issues:
        console.print("\n[bold red]⚠️  Key Issues Found:[/bold red]")
        for i, issue in enumerate(all_issues[:10], 1):
            console.print(f"  {i}. {issue}")

    # ────────────── Consolidated Recommendations ──────────────
    all_recs = []
    all_recs.extend(spf.get("recommendations", []))
    all_recs.extend(dmarc.get("recommendations", []))
    all_recs.extend(dkim.get("recommendations", []))
    all_recs.extend(tls_assessment.get("recommendations", []))

    if all_recs:
        console.print("\n[bold cyan]💡  Top Recommendations:[/bold cyan]")
        for i, rec in enumerate(all_recs[:8], 1):
            console.print(f"  {i}. {rec}")

    # ────────────── Footer ──────────────
    console.print("\n[dim]For more detailed reports, run individual modules:[/dim]")
    console.print(f"  [dim]python -m hisn.scanner.recon {domain}[/dim]")
    console.print(f"  [dim]python -m hisn.scanner.email_security {domain}[/dim]")
    console.print(f"  [dim]python -m hisn.scanner.port_scanner {domain}[/dim]")
    console.print(f"  [dim]python -m hisn.scanner.tls_audit {domain}[/dim]")
    console.print("\n[bold green]✅  Full HISN audit complete![/bold green]\n")


# --------------------------------------------------------------------------
def main():
    if len(sys.argv) < 3 or sys.argv[1] != "scan":
        console.print("[bold red]Usage:[/bold red] python -m hisn scan <domain>")
        console.print("[bold yellow]Example:[/bold yellow] python -m hisn scan bue.edu.eg")
        sys.exit(1)

    target = sys.argv[2]
    run_full_audit(target)


if __name__ == "__main__":
    main()