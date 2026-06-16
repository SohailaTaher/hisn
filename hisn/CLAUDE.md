# HISN — Project Context

## What this is

**HISN** (حصن, Arabic for "fortress") is an **External Attack Surface Management (EASM)** platform for SMBs in the MENA region. It scans an organisation's external-facing assets and surfaces misconfigurations, vulnerabilities, and exposure risks.

This is a final-year cybersecurity capstone / portfolio project. It is being built to be **commercially viable**, not just academic — code quality, tests, clean module boundaries, and clear UX matter.

Repo: https://github.com/SohailaTaher/hisn

---

## Stack

- **Language:** Python 3.11+
- **CLI:** `typer`
- **HTTP:** `httpx` (async-first; do not use `requests`)
- **DNS:** `dnspython`
- **API framework:** `FastAPI`
- **Console output:** `rich` (never raw `print` for user-facing output)
- **Tests:** `pytest`
- **Dev environment:** WSL2 (Ubuntu) on Windows 11, VS Code, Python venv at `.venv/`

---

## Scanner modules

Current state:

| # | Module           | Status                                        |
|---|------------------|-----------------------------------------------|
| 1 | Recon            | ✅ working                                    |
| 2 | Email security   | ✅ working                                    |
| 3 | Port scanning    | ✅ working                                    |
| 4 | TLS/SSL audit    | ✅ working                                    |
| 5 | Nuclei (v3.3.7)  | 🟡 in progress — see "Current work" below     |

**When adding or modifying a scanner module, read at least one existing scanner first and match its structure, naming, error handling, and output format.** Consistency across scanners is more important than individual cleverness.

---

## Conventions

- Async where IO-bound; sync only when there's a real reason.
- Type hints on every function signature. Return types included.
- All scanner modules expose a consistent interface — follow the pattern in existing modules.
- All new code ships with `pytest` tests in `tests/`, mirroring the source tree.
- No new third-party dependency without explicit confirmation — keep the dependency surface small.
- No raw `print()` for user-facing output. Use `rich` (tables, panels, progress bars).
- Errors caught from external tools (Nuclei subprocess, DNS lookups, etc.) must be surfaced clearly, never swallowed.
- Commit messages: short, imperative ("Add Nuclei subprocess wrapper", not "added stuff").

---

## Environment quirks — MENA / Egypt-specific

These are **real production constraints** for the target market and have already bitten this project. Design around them:

- **Port 53 (DNS) is filtered by Egyptian ISPs.** Do not rely on native UDP DNS. Use **JSON DoH via Cloudflare** (`https://cloudflare-dns.com/dns-query`) for any DNS-dependent feature.
- **Port 43 (WHOIS) is filtered.** Do not use classic WHOIS. Use **RDAP** (HTTP-based) instead.
- **General rule:** when designing any feature that depends on outbound network access on a non-standard port, check whether the protocol is filtered in MENA. If yes, find an HTTP/HTTPS-based equivalent before writing the module.

---

## Current work-in-progress

**Week 5 complete (v0.5.1).** Full backend spine working end-to-end:
- FastAPI app with 4 endpoints (POST /scans, GET /scans, GET /scans/{id}, GET /scans/{id}/findings)
- SQLite + SQLModel for persistence (Target, Scan, Finding)
- Celery + Redis for async task execution
- Orchestrator normalizes all 5 scanner outputs into unified Finding shape
- 7 integration tests passing

**Next up: Week 6 — React frontend + PDF reports.**

The frontend will consume the existing API. Three minimum pages: targets list, scan detail view (with severity-grouped findings table), trigger-new-scan form. Then add PDF report generation as a download endpoint on the scan detail page.

## What to do when starting a task

1. Read the most relevant existing module before writing anything new — match its conventions.
2. If a task requires a new dependency, ask before adding it.
3. Write tests in the same change as the feature, not after.
4. If a feature breaks because of network filtering in Egypt, that's a known class of issue — propose an HTTP-based workaround rather than telling the user to change networks.
5. Keep the CLI output readable for non-technical users — HISN's target audience is SMB operators, not security engineers.
