"""
HISN — Scanner Orchestrator
=============================
Cross-scanner coordination layer.

Each scanner module produces its own native result shape (dicts with
score, grade, issues, recommendations, etc).

This module is the **boundary** that translates those native shapes
into the unified Finding format used by the API + DB.

Author: Sohaila Taher Shaker
License: MIT
"""

from hisn.scanner import recon, email_security, port_scanner, tls_audit, vuln_scanner


# ============================================================================
#   Helpers
# ============================================================================

def _grade_from_score(score: int) -> str:
    """Map a numeric score to a letter grade — matches the convention used
    inside each individual scanner module."""
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


# ============================================================================
#   Recon — pure discovery, no scoring
# ============================================================================

def run_recon_scanner(domain: str) -> dict:
    """Run the recon module. Emits info-level findings for discovered data.
    Recon doesn't produce a score (it's discovery, not assessment), so score=None.
    """
    findings = []

    try:
        whois_data = recon.get_whois_info(domain)
        if whois_data and not whois_data.get("error"):
            findings.append({
                "scanner_name": "recon",
                "severity": "info",
                "title": "WHOIS information",
                "description": f"Domain registered with {whois_data.get('registrar', 'unknown registrar')}",
                "raw_data": whois_data,
            })
    except Exception as e:
        findings.append({
            "scanner_name": "recon", "severity": "low",
            "title": "WHOIS lookup failed",
            "description": str(e), "raw_data": {"error": str(e)},
        })

    try:
        dns_data = recon.get_dns_records(domain)
        if dns_data:
            findings.append({
                "scanner_name": "recon",
                "severity": "info",
                "title": "DNS records discovered",
                "description": f"Discovered DNS records across {len(dns_data)} record types",
                "raw_data": dns_data,
            })
    except Exception as e:
        findings.append({
            "scanner_name": "recon", "severity": "low",
            "title": "DNS lookup failed",
            "description": str(e), "raw_data": {"error": str(e)},
        })

    try:
        subdomains = recon.enumerate_subdomains(domain)
        if subdomains:
            preview = ", ".join(subdomains[:5])
            if len(subdomains) > 5:
                preview += f" (+{len(subdomains) - 5} more)"
            findings.append({
                "scanner_name": "recon",
                "severity": "info",
                "title": f"Subdomains discovered ({len(subdomains)})",
                "description": preview,
                "raw_data": {"subdomains": subdomains},
            })
    except Exception as e:
        findings.append({
            "scanner_name": "recon", "severity": "low",
            "title": "Subdomain enumeration failed",
            "description": str(e), "raw_data": {"error": str(e)},
        })

    return {"scanner": "recon", "score": None, "grade": None, "findings": findings}


# ============================================================================
#   Email security — SPF + DMARC + DKIM
# ============================================================================

def _severity_for_email_grade(grade: str) -> str:
    """Map a per-section email-security grade letter to a HISN severity."""
    return {"A": "info", "B": "low", "C": "medium", "D": "high", "F": "critical"}.get(grade, "medium")


def run_email_security_scanner(domain: str) -> dict:
    """Run the email security module (SPF + DMARC + DKIM checks)."""
    spf = email_security.check_spf(domain)
    dmarc = email_security.check_dmarc(domain)
    dkim = email_security.check_dkim(domain)
    overall = email_security.calculate_overall(spf, dmarc, dkim)

    findings = []
    for section, label in [(spf, "SPF"), (dmarc, "DMARC"), (dkim, "DKIM")]:
        issues = section.get("issues", [])
        recs = section.get("recommendations", [])
        section_grade = section.get("grade", "F")
        sev = _severity_for_email_grade(section_grade)
        for i, issue in enumerate(issues):
            description = recs[i] if i < len(recs) else None
            findings.append({
                "scanner_name": "email_security",
                "severity": sev,
                "title": f"{label}: {issue}",
                "description": description,
                "raw_data": {
                    "check": label, "issue": issue, "recommendation": description,
                    "section_grade": section_grade, "section_score": section.get("score"),
                },
            })

    return {
        "scanner": "email_security",
        "score": overall.get("score", 0),
        "grade": overall.get("grade", "F"),
        "findings": findings,
    }


# ============================================================================
#   Port scanner — nmap-based open-port + risk assessment
# ============================================================================

def run_port_scanner_scanner(domain: str) -> dict:
    """Run the port-scan module (nmap → parse → assess risk).
    Tries multiple key patterns for the risky-ports list since exact shape
    of assess_risk's return is uncertain — adjust if needed.
    """
    raw_output = port_scanner.run_nmap_scan(domain)
    ports = port_scanner.parse_nmap_output(raw_output)
    assessment = port_scanner.assess_risk(ports)

    findings = []
    # Try a few common key names for the risky-ports collection
    risky = (
        assessment.get("risky_ports")
        or assessment.get("risky_exposures")
        or assessment.get("risks")
        or []
    )

    if risky and isinstance(risky, list) and risky and isinstance(risky[0], dict):
        # Structured: each item is a dict with port/service/severity/reason
        for rp in risky:
            findings.append({
                "scanner_name": "port_scanner",
                "severity": str(rp.get("severity", "medium")).lower(),
                "title": f"Risky exposure: port {rp.get('port', '?')} ({rp.get('service', 'unknown')})",
                "description": rp.get("reason") or rp.get("why") or rp.get("description"),
                "raw_data": rp,
            })
    else:
        # Fallback: assess_risk uses the tls_audit pattern (issues list of strings)
        issues = assessment.get("issues", [])
        recs = assessment.get("recommendations", [])
        for i, issue in enumerate(issues):
            findings.append({
                "scanner_name": "port_scanner",
                "severity": "medium",
                "title": issue,
                "description": recs[i] if i < len(recs) else None,
                "raw_data": {"issue": issue, "open_ports_count": len(ports)},
            })

    return {
        "scanner": "port_scanner",
        "score": assessment.get("score", 0),
        "grade": assessment.get("grade", "F"),
        "findings": findings,
    }


# ============================================================================
#   TLS audit — (existing, unchanged from Phase 2)
# ============================================================================

def _severity_for_tls_issue(issue: str, has_error: bool) -> str:
    if has_error:
        return "high"
    s = issue.lower()
    if "expired" in s and "ago" in s: return "critical"
    if "self-signed" in s: return "high"
    if "does not cover" in s: return "high"
    if "not currently valid" in s: return "high"
    if "outdated tls version" in s: return "high"
    if "expires in" in s: return "medium"
    if "not modern aead" in s: return "medium"
    return "medium"


def run_tls_audit_scanner(domain: str) -> dict:
    cert_info = tls_audit.fetch_certificate_info(domain)
    assessment = tls_audit.assess_tls(cert_info, domain)
    has_error = bool(cert_info.get("error"))
    issues = assessment.get("issues", [])
    recs = assessment.get("recommendations", [])

    findings = []
    for i, issue in enumerate(issues):
        description = recs[i] if i < len(recs) else None
        findings.append({
            "scanner_name": "tls_audit",
            "severity": _severity_for_tls_issue(issue, has_error),
            "title": issue,
            "description": description,
            "raw_data": {
                "issue": issue, "recommendation": description,
                "cert_subject": cert_info.get("subject"),
                "cert_issuer": cert_info.get("issuer"),
                "days_until_expiry": cert_info.get("days_until_expiry"),
                "tls_version": cert_info.get("tls_version"),
                "cipher": cert_info.get("cipher"),
            },
        })
    return {
        "scanner": "tls_audit",
        "score": assessment.get("score", 0),
        "grade": assessment.get("grade", "F"),
        "findings": findings,
    }


# ============================================================================
#   Vulnerability scanner — Nuclei wrapper
# ============================================================================

def run_vuln_scanner(domain: str) -> dict:
    """Run the Nuclei vulnerability scanner. Includes pre-flight checks for
    Nuclei installation and target reachability — both produce a finding if they fail."""

    if not vuln_scanner.check_nuclei_installed():
        return {
            "scanner": "vuln_scanner", "score": 0, "grade": "F",
            "findings": [{
                "scanner_name": "vuln_scanner", "severity": "high",
                "title": "Nuclei not installed on scanner host",
                "description": "Vulnerability scanning unavailable until Nuclei is installed.",
                "raw_data": {"error": "nuclei_not_installed"},
            }],
        }

    reachable, target_url = vuln_scanner.is_target_reachable(domain)
    if not reachable:
        return {
            "scanner": "vuln_scanner", "score": 0, "grade": "F",
            "findings": [{
                "scanner_name": "vuln_scanner", "severity": "info",
                "title": "Target not reachable for vulnerability scan",
                "description": "Could not establish an HTTP connection to the target.",
                "raw_data": {"domain": domain, "error": "target_unreachable"},
            }],
        }

    raw_findings = vuln_scanner.run_nuclei_scan(target_url)
    by_severity = vuln_scanner.categorize_findings(raw_findings)
    assessment = vuln_scanner.assess_vulnerabilities(by_severity)

    findings = []
    for severity, items in by_severity.items():
        for item in items:
            findings.append({
                "scanner_name": "vuln_scanner",
                "severity": severity,
                "title": item.get("name", "Unknown vulnerability"),
                "description": item.get("description"),
                "raw_data": {
                    "template_id": item.get("template_id"),
                    "matched_at": item.get("matched"),
                    "tags": item.get("tags"),
                    "severity": severity,
                },
            })

    return {
        "scanner": "vuln_scanner",
        "score": assessment.get("score", 0),
        "grade": assessment.get("grade", "F"),
        "findings": findings,
    }


# ============================================================================
#   Aggregator — runs all 5 scanners
# ============================================================================

def run_all_scanners(domain: str) -> dict:
    """Run all 5 scanners. Each one's failure is isolated so a crash in
    one module doesn't kill the whole scan.

    Overall score: simple average of scanners that produced a numeric score.
    Recon is excluded from scoring (it's pure discovery — no assessment).
    """
    scanners = [
        ("recon",          run_recon_scanner),
        ("email_security", run_email_security_scanner),
        ("port_scanner",   run_port_scanner_scanner),
        ("tls_audit",      run_tls_audit_scanner),
        ("vuln_scanner",   run_vuln_scanner),
    ]

    all_findings = []
    scored = []
    per_scanner = {}

    for name, fn in scanners:
        try:
            result = fn(domain)
            all_findings.extend(result.get("findings", []))
            score = result.get("score")
            if score is not None:
                scored.append(score)
            per_scanner[name] = {
                "status": "ok",
                "score": score,
                "grade": result.get("grade"),
                "findings_count": len(result.get("findings", [])),
            }
        except Exception as e:
            all_findings.append({
                "scanner_name": name, "severity": "high",
                "title": f"Scanner '{name}' crashed",
                "description": str(e),
                "raw_data": {"error": str(e), "scanner": name},
            })
            per_scanner[name] = {"status": "failed", "error": str(e)}

    overall_score = round(sum(scored) / len(scored)) if scored else 0
    overall_grade = _grade_from_score(overall_score)

    return {
        "scanner": "all",
        "score": overall_score,
        "grade": overall_grade,
        "findings": all_findings,
        "per_scanner": per_scanner,
    }