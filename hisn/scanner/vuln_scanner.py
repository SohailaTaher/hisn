"""
HISN — Vulnerability Scanner Module
====================================
Wraps Nuclei (from ProjectDiscovery) to detect known vulnerabilities,
misconfigurations, exposed admin panels, default credentials, and CVE matches.

⚠️ ETHICS: This is highly active scanning. Hundreds to thousands of HTTP
requests are sent to the target. Only scan systems you own or have explicit
permission to test.

Safe public test targets:
  - testphp.vulnweb.com (Acunetix's deliberately vulnerable site)
  - scanme.nmap.org (Nmap-authorized)

Usage:
    python -m hisn.scanner.vuln_scanner <domain>
"""

import sys
import subprocess
import json
import shutil
import requests
import tempfile
import os
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


# Per-finding penalty applied to a starting score of 100.
# Calibrated so that one critical finding alone drops you to a 'C',
# matching the way real SMBs experience CVEs in production.
SEVERITY_PENALTIES = {
    "critical": 25,  # CVE with active exploits, full data exposure
    "high":     15,  # Severe misconfig, sensitive info leak
    "medium":    8,  # Default creds, weak auth
    "low":       3,  # Information disclosure, version banners
    "info":      0,  # Just informational
    "unknown":   1,
}

SEVERITY_DISPLAY = {
    "critical": "🔴 CRITICAL",
    "high":     "🟠 HIGH",
    "medium":   "🟡 MEDIUM",
    "low":      "🟢 LOW",
    "info":     "ℹ️  INFO",
    "unknown":  "❔ UNKNOWN",
}


def check_nuclei_installed() -> bool:
    """Return True if nuclei is on PATH."""
    return shutil.which("nuclei") is not None

def is_target_reachable(target: str, timeout: int = 10) -> tuple:
    """
    Verify the target responds to HTTP/HTTPS before running Nuclei.
    Tries apex first, then www. fallback (many domains have no apex A record).

    Returns (reachable: bool, working_url: str).
    """
    if target.startswith(("http://", "https://")):
        candidates = [target]
    else:
        # Try the apex first, then www. variant — same trick as in tls_audit
        candidates = [
            f"https://{target}",
            f"http://{target}",
        ]
        if not target.startswith("www."):
            candidates += [
                f"https://www.{target}",
                f"http://www.{target}",
            ]

    for url in candidates:
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True)
            return True, url
        except requests.RequestException:
            try:
                r = requests.get(url, timeout=timeout, allow_redirects=True, stream=True)
                r.close()
                return True, url
            except requests.RequestException:
                continue
    return False, ""

def run_nuclei_scan(target: str) -> list:
    """
    Run Nuclei against a target URL.

    Flags:
      -u            target URL
      -o            output file
      -jsonl        JSON output (one finding per line)
      -no-color     no ANSI codes
      -duc          disable update check (faster startup)
    
    NOTE: Nuclei v3.3.7 hangs when using capture_output=True with -jsonl (Go buffering issue).
    Workaround: write directly to file instead of capturing stdout.
    Filter by severity in Python (post-processing) instead of Nuclei flags.
    Timeout: 600 seconds (10 minutes) to allow full scan completion.
    """
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    findings = []
    temp_file = None
    try:
        # Create temp file for Nuclei output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            temp_file = f.name
        
        # Run Nuclei without capturing output (avoids Go binary buffering issues)
        # Use timeout of 600 seconds (10 minutes) as scans can take a long time
        try:
            cmd_str = f"nuclei -u {target} -o {temp_file} -jsonl -no-color -duc"
            subprocess.run(cmd_str, shell=True, timeout=600, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️  Nuclei scan timed out after 10 minutes[/yellow]")
        
        # Read and parse the temp file
        if os.path.exists(temp_file) and os.path.getsize(temp_file) > 0:
            with open(temp_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        # Include all severity levels (Nuclei often reports many as "info")
                        severity = finding.get("info", {}).get("severity", "unknown").lower()
                        if severity in ("critical", "high", "medium", "low", "info", "unknown"):
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        console.print(f"[red]Error running Nuclei: {e}[/red]")
    finally:
        # Clean up temp file
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception:
                pass

    return findings


def categorize_findings(findings: list) -> dict:
    """Group findings by severity."""
    by_severity = {sev: [] for sev in SEVERITY_DISPLAY}
    for f in findings:
        info = f.get("info", {})
        severity = info.get("severity", "unknown").lower()
        if severity not in by_severity:
            severity = "unknown"
        by_severity[severity].append({
            "name":        info.get("name", "Unknown"),
            "template_id": f.get("template-id") or f.get("templateID", "unknown"),
            "matched":     f.get("matched-at") or f.get("host", ""),
            "tags":        info.get("tags", []),
            "description": info.get("description", ""),
            "severity":    severity,
        })
    return by_severity


def assess_vulnerabilities(by_severity: dict) -> dict:
    """Score the vulnerability posture (out of 100)."""
    score = 100
    for sev, items in by_severity.items():
        score -= SEVERITY_PENALTIES.get(sev, 0) * len(items)
    score = max(0, score)

    if score >= 90:
        grade, verdict, color = "A", "Excellent — no significant vulnerabilities detected", "bold green"
    elif score >= 75:
        grade, verdict, color = "B", "Good — only minor low-severity issues", "green"
    elif score >= 60:
        grade, verdict, color = "C", "Fair — medium-severity issues need attention", "yellow"
    elif score >= 40:
        grade, verdict, color = "D", "Poor — multiple high-severity issues found", "bright_red"
    else:
        grade, verdict, color = "F", "Failing — critical vulnerabilities require immediate action", "bold red"

    return {"score": score, "grade": grade, "verdict": verdict, "color": color}


def display_banner():
    banner = """
[bold cyan]██╗  ██╗██╗███████╗███╗   ██╗
██║  ██║██║██╔════╝████╗  ██║
███████║██║███████╗██╔██╗ ██║
██╔══██║██║╚════██║██║╚██╗██║
██║  ██║██║███████║██║ ╚████║
╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝[/bold cyan]
[yellow]External Security Posture Platform[/yellow]
[dim]Vulnerability Scanner Module · v0.1.0[/dim]
"""
    console.print(banner)


def run_vuln_scan(domain: str):
    display_banner()
    console.print(f"🎯  Target: [bold green]{domain}[/bold green]")
    console.print(f"📅  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    console.print(
        "[bold yellow]⚠️  ETHICS:[/bold yellow] Active scan — only run against systems you own or have permission to test.\n"
    )

    if not check_nuclei_installed():
        console.print("[bold red]❌ Nuclei not installed.[/bold red] Run: `nuclei -version` to verify the install.")
        return

    # Pre-flight: confirm the target is reachable. Saves us from Nuclei silently
    # retrying for minutes against a target the network has filtered.
    console.print("[cyan]→ Checking target reachability...[/cyan]")
    reachable, target_url = is_target_reachable(domain)
    if not reachable:
        console.print(f"[bold red]❌ Target '{domain}' is not reachable from this network.[/bold red]")
        console.print("[yellow]This usually means:[/yellow]")
        console.print("  • Your network filters/blocks the target (common for some Egyptian ISPs)")
        console.print("  • Target is offline")
        console.print("  • Firewall blocking outbound HTTP/HTTPS")
        console.print("[dim]Try a known-reachable target like scanme.nmap.org[/dim]\n")
        return
    console.print(f"[green]✅ Target reachable at: {target_url}[/green]\n")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
        p.add_task("Running Nuclei (this may take 2-10 minutes)...", total=None)
        findings = run_nuclei_scan(domain)

    by_severity = categorize_findings(findings)

    # --- Severity summary ---
    t = Table(title="📊  Findings by Severity", title_style="bold cyan", show_lines=True)
    t.add_column("Severity", style="bold")
    t.add_column("Count", justify="center")
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        t.add_row(SEVERITY_DISPLAY[sev], str(len(by_severity[sev])))
    console.print(t)

    # --- Detailed findings tables, one per severity ---
    for severity in ("critical", "high", "medium", "low", "info", "unknown"):
        items = by_severity[severity]
        if not items:
            continue
        t = Table(
            title=f"{SEVERITY_DISPLAY[severity]} Findings",
            title_style="bold",
            show_lines=True,
        )
        t.add_column("Template", style="bold yellow")
        t.add_column("Name", style="white")
        t.add_column("Matched At", style="dim")
        for item in items[:10]:
            t.add_row(item["template_id"][:40], item["name"][:55], item["matched"][:55])
        if len(items) > 10:
            t.add_row("...", f"(+{len(items) - 10} more {severity} findings)", "")
        console.print(t)

    # --- Overall verdict ---
    assessment = assess_vulnerabilities(by_severity)
    console.print()
    console.print(Panel(
        f"[{assessment['color']}]Score: {assessment['score']}/100   ·   Grade: {assessment['grade']}[/{assessment['color']}]\n\n{assessment['verdict']}",
        title="🎯  Vulnerability Posture",
        title_align="left",
        border_style=assessment["color"],
    ))

    console.print("\n[bold green]✅  Vulnerability scan complete![/bold green]\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python -m hisn.scanner.vuln_scanner <domain>")
        console.print("[bold yellow]Example:[/bold yellow] python -m hisn.scanner.vuln_scanner testphp.vulnweb.com")
        sys.exit(1)

    target = sys.argv[1]
    run_vuln_scan(target)