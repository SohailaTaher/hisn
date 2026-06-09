"""
HISN — Port Scanner Module
==========================
Wraps Nmap to discover open ports, running services, and software versions
on a target host.

⚠️  ETHICS WARNING: Port scanning is ACTIVE reconnaissance. Packets are sent
directly to the target. Only scan systems you own or have explicit permission
to scan. Random scanning is illegal in most countries.

Safe test targets:
  - scanme.nmap.org (explicitly authorized by Nmap)

Usage:
    python -m hisn.scanner.port_scanner <domain>

Example:
    python -m hisn.scanner.port_scanner scanme.nmap.org

Author: Sohaila Taher Shaker
License: MIT
"""

import sys
import subprocess
import re
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


# Common ports we explicitly check (fast scan).
# These cover ~95% of services SMBs actually expose.
COMMON_PORTS = "21,22,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,8080,8443"

# Ports known to be RISKY when exposed to the internet
RISKY_PORTS = {
    21:   ("FTP",        "🔴 HIGH",   "Unencrypted file transfer — credentials in plaintext"),
    23:   ("Telnet",     "🔴 HIGH",   "Unencrypted shell — should NEVER be exposed"),
    25:   ("SMTP",       "🟡 MEDIUM", "Mail server — fine if patched & authenticated"),
    110:  ("POP3",       "🟡 MEDIUM", "Unencrypted mail retrieval — use 995 (POP3S) instead"),
    135:  ("MS-RPC",     "🔴 HIGH",   "Windows RPC — frequent attack target, never expose"),
    139:  ("NetBIOS",    "🔴 HIGH",   "Windows file sharing — never expose to internet"),
    143:  ("IMAP",       "🟡 MEDIUM", "Unencrypted mail — use 993 (IMAPS) instead"),
    445:  ("SMB",        "🔴 HIGH",   "Windows file sharing — WannaCry vector, never expose"),
    1433: ("MSSQL",      "🔴 HIGH",   "Database — never expose; use VPN/SSH tunnel"),
    3306: ("MySQL",      "🔴 HIGH",   "Database — never expose; use VPN/SSH tunnel"),
    3389: ("RDP",        "🔴 HIGH",   "Remote Desktop — top brute-force target"),
    5432: ("PostgreSQL", "🔴 HIGH",   "Database — never expose; use VPN/SSH tunnel"),
    5900: ("VNC",        "🔴 HIGH",   "Remote desktop — never expose"),
    6379: ("Redis",      "🔴 HIGH",   "In-memory DB — frequent ransom target, never expose"),
    8080: ("HTTP-Alt",   "🟢 LOW",    "Alternate web port — fine if intentional"),
    27017:("MongoDB",    "🔴 HIGH",   "Database — never expose, multiple historical breaches"),
}


def run_nmap_scan(domain: str) -> str:
    """
    Run Nmap against a target with service/version detection.

    Flags explained:
      -Pn        : Skip host discovery (assume host is up — faster, more reliable)
      -sV        : Service/version detection (what's actually running)
      -T4        : Timing template 4 (faster than default, still polite)
      -p <ports> : Only scan our list of common ports
      --open     : Only show open ports in output
    """
    try:
        result = subprocess.run(
            [
                "nmap", "-Pn", "-sV", "-T4",
                "-p", COMMON_PORTS,
                "--open",
                domain,
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        return "[ERROR] nmap not installed"


def parse_nmap_output(raw_output: str) -> list:
    """
    Parse Nmap's text output to extract a list of open ports.

    Nmap output format (lines we care about):
        PORT     STATE SERVICE VERSION
        22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu...
        80/tcp   open  http    Apache httpd 2.4.7
    """
    open_ports = []
    in_port_section = False

    for line in raw_output.splitlines():
        # Detect the start of the port listing
        if re.match(r"PORT\s+STATE\s+SERVICE", line):
            in_port_section = True
            continue
        if not in_port_section:
            continue
        # Empty line = section ended
        if not line.strip():
            in_port_section = False
            continue

        # Match lines like "22/tcp open ssh OpenSSH 6.6.1p1"
        match = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)", line)
        if match:
            port = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version = match.group(5).strip() or "—"
            open_ports.append({
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
            })

    return open_ports


def assess_risk(ports: list) -> dict:
    """
    Assign a risk score to the open-port findings.

    Scoring (out of 100):
      Start at 100, subtract penalty per risky open port:
        🔴 HIGH risk port    -25 points
        🟡 MEDIUM risk port  -10 points
        🟢 LOW risk port      -2 points
        Standard (80/443/22) -0 points (normal & expected)
    """
    score = 100
    risky_findings = []
    expected_findings = []  # 80, 443, 22 are normal

    for p in ports:
        port_num = p["port"]
        if port_num in RISKY_PORTS:
            service_name, severity, why = RISKY_PORTS[port_num]
            if "🔴" in severity:
                score -= 25
            elif "🟡" in severity:
                score -= 10
            else:
                score -= 2
            risky_findings.append({
                "port": port_num,
                "service": service_name,
                "severity": severity,
                "reason": why,
                "version": p["version"],
            })
        elif port_num in (22, 80, 443):
            # SSH/HTTP/HTTPS = expected & normal
            expected_findings.append(p)
        else:
            # Unknown port — small penalty since it's unexpected
            score -= 3
            expected_findings.append(p)

    score = max(0, score)

    if score >= 90:
        grade, verdict, color = "A", "Excellent — minimal attack surface exposed", "bold green"
    elif score >= 75:
        grade, verdict, color = "B", "Good — small attack surface, no critical exposures", "green"
    elif score >= 60:
        grade, verdict, color = "C", "Fair — some exposed services warrant review", "yellow"
    elif score >= 40:
        grade, verdict, color = "D", "Poor — significant attack surface exposed", "bright_red"
    else:
        grade, verdict, color = "F", "Failing — critical services exposed to the internet", "bold red"

    return {
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "color": color,
        "risky": risky_findings,
        "expected": expected_findings,
    }


def display_banner():
    banner = """
[bold cyan]██╗  ██╗██╗███████╗███╗   ██╗
██║  ██║██║██╔════╝████╗  ██║
███████║██║███████╗██╔██╗ ██║
██╔══██║██║╚════██║██║╚██╗██║
██║  ██║██║███████║██║ ╚████║
╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝[/bold cyan]
[yellow]External Security Posture Platform[/yellow]
[dim]Port Scanner Module · v0.1.0[/dim]
"""
    console.print(banner)


def run_port_scan(domain: str):
    """Orchestrate the port scan and print the report."""
    display_banner()
    console.print(f"🎯  Target: [bold green]{domain}[/bold green]")
    console.print(f"📅  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    console.print(
        "[bold yellow]⚠️  ETHICS:[/bold yellow] Only scan systems you own or have permission to scan.\n"
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        transient=True,
    ) as p:
        p.add_task("Running Nmap scan (this can take 30-90 seconds)...", total=None)
        raw = run_nmap_scan(domain)

    if not raw or "[ERROR]" in raw:
        console.print("[bold red]❌ Scan failed — check Nmap installation and target reachability[/bold red]")
        return

    open_ports = parse_nmap_output(raw)
    assessment = assess_risk(open_ports)

    # --- Open Ports Table ---
    if open_ports:
        t = Table(title=f"🔍  Open Ports Discovered ({len(open_ports)})", title_style="bold cyan", show_lines=True)
        t.add_column("Port", style="bold yellow")
        t.add_column("Protocol")
        t.add_column("Service", style="green")
        t.add_column("Version Detected", style="white")
        for port in open_ports:
            t.add_row(
                str(port["port"]),
                port["protocol"],
                port["service"],
                port["version"][:80],
            )
        console.print(t)
    else:
        console.print("[yellow]No open ports found in scanned range.[/yellow]")

    # --- Risky Findings Table ---
    if assessment["risky"]:
        t = Table(title="⚠️  Risky Exposures", title_style="bold red", show_lines=True)
        t.add_column("Port", style="bold yellow")
        t.add_column("Service")
        t.add_column("Severity")
        t.add_column("Why it matters", style="white")
        for r in assessment["risky"]:
            t.add_row(str(r["port"]), r["service"], r["severity"], r["reason"])
        console.print(t)

    # --- Overall Verdict ---
    console.print()
    console.print(Panel(
        f"[{assessment['color']}]Score: {assessment['score']}/100   ·   Grade: {assessment['grade']}[/{assessment['color']}]\n\n{assessment['verdict']}",
        title="🎯  Network Exposure Posture",
        title_align="left",
        border_style=assessment["color"],
    ))

    console.print("\n[bold green]✅  Port scan complete![/bold green]\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python -m hisn.scanner.port_scanner <domain>")
        console.print("[bold yellow]Example:[/bold yellow] python -m hisn.scanner.port_scanner scanme.nmap.org")
        sys.exit(1)

    target = sys.argv[1]
    run_port_scan(target)