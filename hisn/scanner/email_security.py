"""
HISN — Email Security Audit Module
===================================
Audits a domain's email security posture by checking:
  - SPF   (Sender Policy Framework)            — anti-spoofing
  - DMARC (Domain Auth, Reporting, Conformance) — enforcement policy
  - DKIM  (DomainKeys Identified Mail)          — cryptographic signing

Why this matters:
  Phishing and Business Email Compromise (BEC) are the #1 attack
  vector against SMBs. Properly configured SPF/DKIM/DMARC make
  it dramatically harder for attackers to impersonate the business.

Usage:
    python -m hisn.scanner.email_security <domain>

Example:
    python -m hisn.scanner.email_security gmail.com

Author: Sohaila Taher Shaker
License: MIT
"""

import sys
from datetime import datetime

import dns.resolver
from rich.console import Console
from hisn.scanner.dns_utils import query_dns
from rich.table import Table
from rich.panel import Panel

console = Console()


# Selectors used by major email providers. We can't enumerate every
# possible selector in DNS, but probing common ones catches ~95% of
# real-world configurations.
COMMON_DKIM_SELECTORS = [
    # Generic
    "default", "selector", "dkim", "mail", "smtp",

    # Microsoft 365 / Outlook
    "selector1", "selector2",

    # Google Workspace + Gmail (date-based selectors)
    "google", "20230601", "20240601", "20250601", "20250101",

    # SendGrid, Mailchimp, Mailgun, etc.
    "s1", "s2", "sm", "k1", "k2", "k3",
    "mailgun", "mg", "mailchimp",

    # Other common patterns
    "key1", "key2", "everlytickey1", "everlytickey2",
    "mxvault", "scph0922", "domk", "everlyticdkim",
]


# ---------------------------------------------------------------------------
# Low-level helper
# ---------------------------------------------------------------------------
def get_txt_records(domain: str) -> list:
    """Fetch TXT records via DoH (bypasses port 53 blocks)."""
    return query_dns(domain, "TXT")


# ---------------------------------------------------------------------------
# SPF Check
# ---------------------------------------------------------------------------
def check_spf(domain: str) -> dict:
    """
    Find and grade the SPF record.

    Scoring (out of 30):
      -all       → 30 (strict, attackers can't spoof)
      ~all       → 25 (soft fail, emails get marked but still delivered)
      redirect=  → 22 (delegated — usually safe)
      ?all       → 15 (neutral, no protection)
      no all     → 10 (incomplete)
      +all       →  5 (permissive — DANGEROUS, anyone can send as you)
      missing    →  0
    """
    txt_records = get_txt_records(domain)
    spf_record = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)

    result = {
        "exists": spf_record is not None,
        "record": spf_record,
        "policy": None,
        "score": 0,
        "grade": "F",
        "issues": [],
        "recommendations": [],
    }

    if not spf_record:
        result["issues"].append("No SPF record found")
        result["recommendations"].append(
            "Add an SPF record. If you don't send email: 'v=spf1 -all'. "
            "If you use Google Workspace: 'v=spf1 include:_spf.google.com -all'."
        )
        return result

    rec_lower = spf_record.lower()
    if "-all" in rec_lower:
        result.update(policy="strict (-all)", score=30, grade="A")
    elif "~all" in rec_lower:
        result.update(policy="soft fail (~all)", score=25, grade="B")
    elif "redirect=" in rec_lower:
        result.update(policy="redirect (delegated)", score=22, grade="B")
    elif "?all" in rec_lower:
        result.update(policy="neutral (?all)", score=15, grade="C")
        result["issues"].append("SPF policy is 'neutral' — provides no enforcement")
        result["recommendations"].append("Change SPF terminator from '?all' to '~all' or '-all'")
    elif "+all" in rec_lower:
        result.update(policy="permissive (+all) — DANGEROUS", score=5, grade="F")
        result["issues"].append("SPF policy is '+all' — ANY server can send mail as you!")
        result["recommendations"].append("URGENT: Replace '+all' with '-all' immediately")
    else:
        result.update(policy="no terminator (incomplete)", score=10, grade="D")
        result["issues"].append("SPF record has no 'all' terminator or redirect")
        result["recommendations"].append("Add '-all' or '~all' at the end of your SPF record")

    return result


# ---------------------------------------------------------------------------
# DMARC Check
# ---------------------------------------------------------------------------
def check_dmarc(domain: str) -> dict:
    """
    Find and grade the DMARC record (located at _dmarc.<domain>).

    Scoring (out of 50):
      p=reject     → 50 (strictest — failed mail is rejected)
      p=quarantine → 35 (medium — failed mail goes to spam)
      p=none       → 15 (monitor only — provides reporting, no protection)
      missing      →  0
    """
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = get_txt_records(dmarc_domain)
    dmarc_record = next((r for r in txt_records if r.lower().startswith("v=dmarc1")), None)

    result = {
        "exists": dmarc_record is not None,
        "record": dmarc_record,
        "policy": None,
        "score": 0,
        "grade": "F",
        "issues": [],
        "recommendations": [],
    }

    if not dmarc_record:
        result["issues"].append("No DMARC record found")
        result["recommendations"].append(
            f"Add a DMARC TXT record at _dmarc.{domain}. Start with: "
            "'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com' to monitor, "
            "then upgrade to p=quarantine, then p=reject."
        )
        return result

    # Parse policy from "p=" tag
    parts = [p.strip() for p in dmarc_record.split(";")]
    policy = next((p[2:].strip() for p in parts if p.lower().startswith("p=")), None)

    if policy == "reject":
        result.update(policy="reject (strictest)", score=50, grade="A")
    elif policy == "quarantine":
        result.update(policy="quarantine (medium)", score=35, grade="B")
        result["issues"].append("DMARC policy is 'quarantine' — consider upgrading to 'reject'")
        result["recommendations"].append("After monitoring confirms legit email isn't failing, change p=quarantine to p=reject")
    elif policy == "none":
        result.update(policy="none (monitor only)", score=15, grade="C")
        result["issues"].append("DMARC policy is 'none' — reporting only, no real protection")
        result["recommendations"].append("Move from p=none to p=quarantine once you've reviewed reports")
    else:
        result.update(policy=f"unknown ({policy})", score=10, grade="D")
        result["issues"].append(f"DMARC policy '{policy}' is unrecognized")

    # Check for reporting address
    has_rua = any(p.lower().startswith("rua=") for p in parts)
    if not has_rua:
        result["issues"].append("DMARC has no 'rua' reporting address — you can't see attack attempts")
        result["recommendations"].append("Add 'rua=mailto:dmarc@yourdomain.com' to receive failure reports")

    return result


# ---------------------------------------------------------------------------
# DKIM Check
# ---------------------------------------------------------------------------
def check_dkim(domain: str) -> dict:
    """
    Probe common DKIM selectors. Selectors are like 'usernames'
    for DKIM keys, and we have to guess them — they're not enumerable.

    Scoring (out of 20):
      any selector found → 20
      none found         →  0  (does NOT mean DKIM isn't configured —
                                just that the selector isn't common)
    """
    result = {
        "exists": False,
        "selectors_found": [],
        "score": 0,
        "grade": "F",
        "issues": [],
        "recommendations": [],
    }

    for selector in COMMON_DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records = get_txt_records(dkim_domain)
        for record in records:
            if "v=DKIM1" in record or "k=rsa" in record:
                result["selectors_found"].append(selector)
                result["exists"] = True
                break

    if result["exists"]:
        result.update(score=20, grade="A")
    else:
        result["issues"].append(
            "No DKIM records found via common selectors. "
            "(DKIM may still be configured with a custom selector.)"
        )
        result["recommendations"].append(
            "Configure DKIM with your email provider so outbound mail can be cryptographically verified."
        )

    return result


# ---------------------------------------------------------------------------
# Overall grade
# ---------------------------------------------------------------------------
def calculate_overall(spf, dmarc, dkim) -> dict:
    """Combine the three scores into an overall A–F grade."""
    total = spf["score"] + dmarc["score"] + dkim["score"]
    if total >= 90:
        return {"score": total, "grade": "A", "verdict": "Excellent — domain well-protected against spoofing", "color": "bold green"}
    if total >= 75:
        return {"score": total, "grade": "B", "verdict": "Good — solid posture with minor improvements possible", "color": "green"}
    if total >= 60:
        return {"score": total, "grade": "C", "verdict": "Fair — basics in place but real risk remains", "color": "yellow"}
    if total >= 40:
        return {"score": total, "grade": "D", "verdict": "Poor — significant email security weaknesses", "color": "bright_red"}
    return {"score": total, "grade": "F", "verdict": "Failing — domain is highly vulnerable to spoofing & phishing", "color": "bold red"}


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
def display_banner():
    banner = """
[bold cyan]██╗  ██╗██╗███████╗███╗   ██╗
██║  ██║██║██╔════╝████╗  ██║
███████║██║███████╗██╔██╗ ██║
██╔══██║██║╚════██║██║╚██╗██║
██║  ██║██║███████║██║ ╚████║
╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝[/bold cyan]
[yellow]External Security Posture Platform[/yellow]
[dim]Email Security Audit Module · v0.1.0[/dim]
"""
    console.print(banner)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def run_email_audit(domain: str):
    display_banner()
    console.print(f"🎯  Target: [bold green]{domain}[/bold green]")
    console.print(f"📅  Audit started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    console.print("[cyan]→ Checking SPF...[/cyan]")
    spf = check_spf(domain)

    console.print("[cyan]→ Checking DMARC...[/cyan]")
    dmarc = check_dmarc(domain)

    console.print("[cyan]→ Probing DKIM selectors...[/cyan]")
    dkim = check_dkim(domain)
    console.print()

    # --- SPF Table ---
    t = Table(title="📧  SPF — Sender Policy Framework", title_style="bold cyan", show_lines=True)
    t.add_column("Field", style="bold yellow"); t.add_column("Value", style="white")
    t.add_row("Exists", "✅ Yes" if spf["exists"] else "❌ No")
    if spf["record"]:
        rec = spf["record"]
        t.add_row("Record", rec[:120] + ("..." if len(rec) > 120 else ""))
    t.add_row("Policy", str(spf["policy"]) if spf["policy"] else "—")
    t.add_row("Score", f"{spf['score']}/30  (Grade {spf['grade']})")
    console.print(t)

    # --- DMARC Table ---
    t = Table(title="🛡️  DMARC — Authentication Policy", title_style="bold cyan", show_lines=True)
    t.add_column("Field", style="bold yellow"); t.add_column("Value", style="white")
    t.add_row("Exists", "✅ Yes" if dmarc["exists"] else "❌ No")
    if dmarc["record"]:
        rec = dmarc["record"]
        t.add_row("Record", rec[:120] + ("..." if len(rec) > 120 else ""))
    t.add_row("Policy", str(dmarc["policy"]) if dmarc["policy"] else "—")
    t.add_row("Score", f"{dmarc['score']}/50  (Grade {dmarc['grade']})")
    console.print(t)

    # --- DKIM Table ---
    t = Table(title="🔑  DKIM — Cryptographic Signing", title_style="bold cyan", show_lines=True)
    t.add_column("Field", style="bold yellow"); t.add_column("Value", style="white")
    t.add_row("Exists", "✅ Yes" if dkim["exists"] else "❌ Not found in common selectors")
    t.add_row("Selectors Found", ", ".join(dkim["selectors_found"]) or "—")
    t.add_row("Score", f"{dkim['score']}/20  (Grade {dkim['grade']})")
    console.print(t)

    # --- Overall verdict ---
    overall = calculate_overall(spf, dmarc, dkim)
    console.print()
    console.print(Panel(
        f"[{overall['color']}]Score: {overall['score']}/100   ·   Grade: {overall['grade']}[/{overall['color']}]\n\n{overall['verdict']}",
        title="🎯  Overall Email Security Posture",
        title_align="left",
        border_style=overall["color"],
    ))

    # --- Issues & recommendations ---
    issues = spf["issues"] + dmarc["issues"] + dkim["issues"]
    recs = spf["recommendations"] + dmarc["recommendations"] + dkim["recommendations"]

    if issues:
        console.print("\n[bold red]⚠️  Issues Found:[/bold red]")
        for i, x in enumerate(issues, 1):
            console.print(f"  {i}. {x}")

    if recs:
        console.print("\n[bold cyan]💡  Recommendations:[/bold cyan]")
        for i, x in enumerate(recs, 1):
            console.print(f"  {i}. {x}")

    console.print("\n[bold green]✅  Email security audit complete![/bold green]\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python -m hisn.scanner.email_security <domain>")
        console.print("[bold yellow]Example:[/bold yellow] python -m hisn.scanner.email_security gmail.com")
        sys.exit(1)

    target = sys.argv[1]
    run_email_audit(target)