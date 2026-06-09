
<div align="center">

# 🛡️ HISN
### حصن — Arabic for "Fortress"

**External Security Posture Platform for Small & Medium Businesses**

*Know your attack surface before attackers do.*

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.12+-blue)
![Made in Egypt](https://img.shields.io/badge/made%20in-Egypt%20🇪🇬-red)

</div>

---

## 🌍 The Problem

Small and medium businesses (SMBs) are the **#1 target** for cybercriminals — yet they're the least equipped to defend themselves:

- **43% of cyberattacks target SMBs** (Verizon DBIR)
- **60% of breached SMBs close within 6 months**
- **Egypt's Personal Data Protection Law (151/2020)** can fine non-compliant businesses up to **EGP 5 million**
- Enterprise security tools (SecurityScorecard, BitSight, UpGuard) charge **$20K–$50K/year** — far beyond SMB budgets

There is no affordable, localized **External Attack Surface Management (EASM)** solution for SMBs in the MENA region.

**HISN closes that gap.**

---

## 🎯 What HISN Does

A small business owner enters their company domain (e.g. `my-pharmacy.com`) — HISN automatically scans every internet-facing weakness an attacker could exploit:

### 🔍 External Reconnaissance
- Subdomain enumeration & asset discovery
- Exposed services and open ports
- Technology fingerprinting (WordPress, CMS, frameworks)

### 📧 Email Security
- SPF, DKIM, DMARC record analysis
- Domain spoofing risk assessment

### 🔐 TLS / SSL Audit
- Certificate validity & expiry tracking
- Weak cipher detection
- Configuration scoring

### 🦠 Vulnerability Assessment
- Known CVE detection (via Nuclei templates)
- WordPress-specific vulnerability scanning
- Dangling DNS records & typosquatting detection

### 📊 Reporting & Compliance
- Security score (A–F, credit-score style)
- Prioritized fix recommendations in plain language
- Downloadable PDF reports (bilingual: Arabic & English)
- Monthly automated re-scans
- **Egyptian PDPL compliance mapping**

---

## 🏗️ High-Level Architecture

┌──────────────┐      ┌──────────────┐      ┌────────────────────┐
│  React UI    │─────▶│  FastAPI     │─────▶│  Scanner Engine    │
│  (Dashboard) │      │  Backend     │      │  (Python)          │
└──────────────┘      └──────┬───────┘      └────────┬───────────┘
│                       │
▼                       ▼
┌─────────────┐         ┌──────────────────┐
│ PostgreSQL  │         │  Nmap · Nuclei   │
│ (Results)   │         │  Subfinder       │
└─────────────┘         │  testssl · WPScan│
│  External APIs   │
└──────────────────┘

📐 *Detailed architecture diagram coming in [`docs/architecture.md`](docs/architecture.md).*

---

## 🛠️ Tech Stack

| Layer | Tools |
|-------|-------|
| **Scanner Engine** | Python 3.12+, Nmap, Nuclei, Subfinder, testssl.sh, WPScan, dnspython |
| **Backend API** | FastAPI, Celery, Redis |
| **Database** | PostgreSQL |
| **Frontend** | React, TailwindCSS |
| **Reports** | ReportLab (PDF generation) |
| **Threat Intel** | VirusTotal, AbuseIPDB, Shodan, HaveIBeenPwned APIs |
| **DevOps** | Docker, Docker Compose, GitHub Actions |

---

## 🗺️ Roadmap — Summer 2026 Sprint

- [x] **Week 1** — Project setup, repository structure, problem validation
- [ ] **Week 2** — Core scanner engine (subdomain enumeration, port scanning)
- [ ] **Week 3** — TLS, DNS, email security modules
- [ ] **Week 4** — Vulnerability scanning, scoring engine
- [ ] **Week 5** — FastAPI backend, async job queue with Celery
- [ ] **Week 6** — React frontend, PDF report generation
- [ ] **Week 7** — Authentication, monthly re-scans, polish
- [ ] **Week 8** — Deployment, beta testing, full documentation

---

## 🚀 Getting Started

> 🚧 **Status:** HISN is under active development. Full setup instructions arrive once the MVP scanner is functional (target: Week 2).

For now, see [`docs/development.md`](docs/development.md) for project structure and contribution notes.

---

## 👩‍💻 Author

**Sohaila Taher Shaker**
Final-year Computer Science student · Cybersecurity specialization
🇬🇧 The British University in Egypt × London South Bank University

🔗 [GitHub](https://github.com/SohailaTaher) · ✉️ sohaila.taher.shaker@gmail.com

---

## 📄 License

MIT — see [`LICENSE`](LICENSE) for details.
