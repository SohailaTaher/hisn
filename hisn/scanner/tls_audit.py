"""
HISN — TLS / SSL Certificate Audit Module
==========================================
Connects to the target on port 443 and analyzes:
  - Certificate validity (not expired / not yet valid)
  - Issuer (which CA signed it)
  - Subject + SAN match (cert actually covers the domain)
  - Days until expiration
  - TLS version (1.0/1.1 = bad, 1.2/1.3 = good)
  - Cipher suite (modern AEAD = good)
  - Self-signed detection

Pure Python — uses only stdlib ssl + socket. No external CLI tools.

Usage:
    python -m hisn.scanner.tls_audit <domain>

Example:
    python -m hisn.scanner.tls_audit github.com

Author: Sohaila Taher Shaker
License: MIT
"""

import sys
import ssl
import socket
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def fetch_certificate_info(domain: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Perform a TLS handshake to the target and extract certificate + crypto details.

    Uses Python's stdlib ssl module. If the certificate fails verification
    (expired, self-signed, wrong domain), the error itself is recorded
    as a finding — we don't pretend a broken cert is fine.
    """
    result = {
        "valid": False,
        "issuer": "Unknown",
        "subject": "Unknown",
        "san": [],
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "tls_version": None,
        "cipher": None,
        "self_signed": False,
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["tls_version"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher"] = cipher_info[0]

                if cert:
                    # Subject (whom the cert is for)
                    subject_dict = dict(x[0] for x in cert.get("subject", []))
                    result["subject"] = subject_dict.get("commonName", "Unknown")

                    # Issuer (the CA that signed it)
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    result["issuer"] = (
                        issuer_dict.get("organizationName")
                        or issuer_dict.get("commonName")
                        or "Unknown"
                    )

                    # Subject Alternative Names (other domains this cert covers)
                    san = cert.get("subjectAltName", [])
                    result["san"] = [s[1] for s in san if s[0] == "DNS"]

                    # Dates (parse Nmap-style "Jan  1 00:00:00 2025 GMT")
                    not_before_str = cert.get("notBefore", "")
                    not_after_str = cert.get("notAfter", "")
                    try:
                        result["not_before"] = datetime.strptime(
                            not_before_str, "%b %d %H:%M:%S %Y GMT"
                        ).replace(tzinfo=timezone.utc)
                        result["not_after"] = datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y GMT"
                        ).replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        result["days_until_expiry"] = (result["not_after"] - now).days
                        result["valid"] = result["not_before"] <= now <= result["not_after"]
                    except ValueError:
                        pass

                    # Self-signed: subject == issuer
                    result["self_signed"] = (subject_dict == issuer_dict)

        return result

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Cert verification failed: {e.reason or e}"
    except socket.gaierror:
        result["error"] = "DNS resolution failed"
    except socket.timeout:
        result["error"] = "Connection timed out (target slow or port 443 blocked)"
    except ConnectionRefusedError:
        result["error"] = "Connection refused (no HTTPS on port 443)"
    except ssl.SSLError as e:
        result["error"] = f"SSL/TLS protocol error: {e.reason or e}"
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result


def domain_matches_cert(target: str, cert_info: dict) -> bool:
    """Check if the target domain is covered by the cert (CN or SAN, with wildcard support)."""
    target = target.lower()
    sans = [s.lower() for s in cert_info.get("san", [])]
    subject = cert_info.get("subject", "").lower()

    if target == subject or target in sans:
        return True

    # Wildcard match: *.example.com covers foo.example.com
    for san in sans:
        if san.startswith("*."):
            base = san[2:]
            if target.endswith(base) and target.count(".") == base.count(".") + 1:
                return True
    return False


def assess_tls(cert_info: dict, target: str) -> dict:
    """
    Score the TLS posture (out of 100):
      Valid (not expired):              25
      Domain match (in CN/SAN):         15
      Not self-signed:                  15
      ≥30 days until expiry:            15
      TLS 1.2 or 1.3:                   15
      Modern AEAD cipher (GCM/ChaCha):  15
    """
    if cert_info.get("error"):
        return {
            "score": 0,
            "grade": "F",
            "verdict": f"Failed to establish TLS: {cert_info['error']}",
            "color": "bold red",
            "issues": [cert_info["error"]],
            "recommendations": ["Ensure HTTPS is configured correctly on port 443"],
        }

    score = 0
    issues = []
    recs = []

    # Validity period
    if cert_info["valid"]:
        score += 25
    else:
        issues.append("Certificate is not currently valid (expired or not yet valid)")
        recs.append("Renew the SSL certificate immediately")

    # Domain match
    if domain_matches_cert(target, cert_info):
        score += 15
    else:
        issues.append(f"Certificate does not cover '{target}' in CN or SAN")
        recs.append("Re-issue the certificate including the correct hostname")

    # Self-signed
    if not cert_info["self_signed"]:
        score += 15
    else:
        issues.append("Certificate is self-signed — not trusted by browsers")
        recs.append("Replace with a CA-signed certificate (Let's Encrypt is free)")

    # Days until expiry
    days = cert_info.get("days_until_expiry")
    if days is not None:
        if days >= 30:
            score += 15
        elif days >= 0:
            issues.append(f"Certificate expires in {days} days (renew before <30 days)")
            recs.append(f"Renew certificate (only {days} days left)")
        else:
            issues.append(f"Certificate EXPIRED {abs(days)} days ago")
            recs.append("URGENT: certificate is already expired — renew immediately")

    # TLS version
    tls_ver = cert_info.get("tls_version", "")
    if tls_ver in ("TLSv1.3", "TLSv1.2"):
        score += 15
    else:
        issues.append(f"Outdated TLS version: {tls_ver}")
        recs.append("Disable TLS 1.0/1.1 — require TLS 1.2 or 1.3 only")

    # Cipher strength
    cipher = (cert_info.get("cipher") or "").upper()
    if any(kw in cipher for kw in ("GCM", "CHACHA20", "POLY1305")):
        score += 15
    elif cipher:
        issues.append(f"Cipher in use is not modern AEAD: {cipher}")
        recs.append("Prioritize AES-GCM or ChaCha20-Poly1305 cipher suites")

    # Grade
    if score >= 90:
        grade, verdict, color = "A", "Excellent — modern TLS configuration", "bold green"
    elif score >= 75:
        grade, verdict, color = "B", "Good — solid TLS with minor improvements possible", "green"
    elif score >= 60:
        grade, verdict, color = "C", "Fair — TLS works but has weaknesses", "yellow"
    elif score >= 40:
        grade, verdict, color = "D", "Poor — significant TLS issues", "bright_red"
    else:
        grade, verdict, color = "F", "Failing — TLS broken or severely misconfigured", "bold red"

    return {
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "color": color,
        "issues": issues,
        "recommendations": recs,
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
[dim]TLS / SSL Audit Module · v0.1.0[/dim]
"""
    console.print(banner)


def run_tls_audit(domain: str):
    display_banner()
    console.print(f"🎯  Target: [bold green]{domain}[/bold green]")
    console.print(f"📅  Audit started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    console.print("[cyan]→ Connecting to port 443 and fetching certificate...[/cyan]\n")

    cert_info = fetch_certificate_info(domain)

    # --- Certificate Details Table ---
    t = Table(title="📜  Certificate Details", title_style="bold cyan", show_lines=True)
    t.add_column("Field", style="bold yellow")
    t.add_column("Value", style="white")

    if cert_info.get("error"):
        t.add_row("Status", f"[bold red]❌ {cert_info['error']}[/bold red]")
    else:
        t.add_row("Subject (CN)", str(cert_info.get("subject", "—")))
        t.add_row("Issuer", str(cert_info.get("issuer", "—")))
        t.add_row("Valid From", str(cert_info.get("not_before", "—")))
        t.add_row("Valid Until", str(cert_info.get("not_after", "—")))

        days = cert_info.get("days_until_expiry")
        if days is not None:
            if days < 0:
                expiry_text = f"[bold red]EXPIRED {abs(days)} days ago[/bold red]"
            elif days < 30:
                expiry_text = f"[bold yellow]{days} days remaining (renew soon!)[/bold yellow]"
            else:
                expiry_text = f"[green]{days} days remaining[/green]"
            t.add_row("Days to Expiry", expiry_text)

        san_text = ", ".join(cert_info.get("san", [])[:8])
        if len(cert_info.get("san", [])) > 8:
            san_text += f"  (+{len(cert_info['san']) - 8} more)"
        t.add_row("Subject Alt Names", san_text or "—")
        t.add_row("Self-Signed", "🔴 YES" if cert_info.get("self_signed") else "✅ No")
    console.print(t)

    # --- TLS Connection Details Table ---
    t = Table(title="🔒  TLS Connection", title_style="bold cyan", show_lines=True)
    t.add_column("Field", style="bold yellow")
    t.add_column("Value", style="white")
    t.add_row("TLS Version", str(cert_info.get("tls_version") or "—"))
    t.add_row("Cipher Suite", str(cert_info.get("cipher") or "—"))
    console.print(t)

    # --- Overall Verdict ---
    assessment = assess_tls(cert_info, domain)
    console.print()
    console.print(Panel(
        f"[{assessment['color']}]Score: {assessment['score']}/100   ·   Grade: {assessment['grade']}[/{assessment['color']}]\n\n{assessment['verdict']}",
        title="🎯  TLS Security Posture",
        title_align="left",
        border_style=assessment["color"],
    ))

    if assessment["issues"]:
        console.print("\n[bold red]⚠️  Issues Found:[/bold red]")
        for i, x in enumerate(assessment["issues"], 1):
            console.print(f"  {i}. {x}")

    if assessment["recommendations"]:
        console.print("\n[bold cyan]💡  Recommendations:[/bold cyan]")
        for i, x in enumerate(assessment["recommendations"], 1):
            console.print(f"  {i}. {x}")

    console.print("\n[bold green]✅  TLS audit complete![/bold green]\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python -m hisn.scanner.tls_audit <domain>")
        console.print("[bold yellow]Example:[/bold yellow] python -m hisn.scanner.tls_audit github.com")
        sys.exit(1)

    target = sys.argv[1]
    run_tls_audit(target)