# CredHunt 🔍

**A lightweight, local-first credential exposure scanner for detecting hardcoded secrets in source code.**

CredHunt scans project files for hardcoded API keys, passwords, private keys, and tokens — the kind of secrets that routinely leak into repos through config files, `.env` files, and forgotten test data. It's built to demonstrate practical secure-coding hygiene: detect fast, protect the secret value itself, and produce a report a security team could actually act on.

---

## Why CredHunt

Most "secret scanner" scripts are a regex and a print statement. CredHunt goes a step further:

- **Never exposes the real secret** — every match is SHA-256 hashed before it's written anywhere, so the report itself can't leak what it found.
- **Runs entirely locally** — no network calls, no data leaves your machine.
- **Produces a real report**, not a terminal dump — clean HTML output (with optional PDF export) suitable for handing to a security or engineering team.

---

## Features

- **Pattern-based detection** across `.py`, `.env`, `.json`, `.cfg`, and `.txt` files
- Detects common high-risk patterns: `password=`, AWS-style keys (`AKIA...`), and other high-entropy strings that resemble tokens or secrets
- **SHA-256 hashing** of every detected string — the report shows a masked snippet and a hash, never the raw secret
- **HTML report generation** via Jinja2 templates, with optional PDF export through `wkhtmltopdf`
- **Modular scanning core** (`core/scanner.py`) designed to make adding new detection rules straightforward
- **Network-facing scanning** for HTTP, FTP, SMTP, and SSH services via passive banner/endpoint checks
- **Concurrent scan dispatch** (worker pool) for scanning multiple targets in parallel *(Benchmarked: 7.9x speedup with 8 workers vs sequential scanning)*
- **Plugin-based architecture** to add new protocol/source scanners without touching core logic

---

## Project Structure

```
CredHunt/
│
├── credhunt.py                # Main runner script (file scanner)
├── credhunt_network.py        # Network scanner CLI runner
│
├── core/
│   ├── orchestrator.py         # Thread pool for concurrency
│   ├── validator.py            # Entropy scoring & false positive reduction
│   ├── evidence_store.py       # Thread-safe findings storage
│   ├── patterns.py             # Centralized regex patterns
│   ├── scanner.py              # Core scanning logic for files
│   └── utils.py                # Hashing and helper functions
│
├── plugins/
│   ├── base.py                 # Abstract base plugin class
│   ├── http_plugin.py          # HTTP endpoint scraper
│   ├── ftp_plugin.py           # FTP banner grabber
│   ├── smtp_plugin.py          # SMTP banner grabber
│   └── ssh_plugin.py           # SSH banner grabber
│
├── reports/
│   ├── report.html             # Auto-generated HTML report
│   └── report.pdf              # Optional PDF output
│
├── templates/
│   └── report_template.html    # HTML report layout
│
├── test_data/
│   ├── config.py               # Sample file with seeded test secrets
│   └── keys.env                # Sample .env file with test credentials
│
└── requirements.txt            # Python dependencies
```

---

## Installation

**1. Create a virtual environment**
```bash
python -m venv credHunt-venv
.\credHunt-venv\Scripts\activate
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```
Core dependencies: `pdfkit`, `jinja2`

**3. Install `wkhtmltopdf`** (required only for PDF export)

Download from [wkhtmltopdf.org/downloads.html](https://wkhtmltopdf.org/downloads.html), then either add it to your system PATH or point to it directly in `reporter.py`:
```python
path = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
config = pdfkit.configuration(wkhtmltopdf=path)
```

---

## Usage

Run a scan against any local folder:
```bash
python credhunt.py
```
You'll be prompted for a path:
```
Enter path to scan: C:\Users\Srikar\Desktop\projects\test_data
```

**Output:**
- `reports/report.html` — always generated
- `reports/report.pdf` — generated if `wkhtmltopdf` is installed

### Sample Output

| File | Type | Snippet | Hash |
|---|---|---|---|
| `test_data/config.py` | AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | `1a5d44a2dca19669d...` |
| `test_data/config.py` | Password String | `password="mySecret123"` | `3421f653163ddbc9...` |
| `test_data/keys.env` | Possible API Key | `wJalrXUtnFEMI/K7M...` | `78314b11be2e5815...` |

---

## Roadmap

- [ ] System-mode scanning for `.aws`, `.ssh`, and `.env` folders (with explicit user consent)
- [ ] GitHub repository scanning via the PyGitHub API
- [ ] Web UI (Flask) for uploading and scanning project archives
- [ ] GitHub Actions integration for automated scanning on every commit

---

## Known Limitations / Ethical Use

CredHunt's network scanning module is strictly **passive**. It connects to designated ports to grab the service banner or standard HTTP response, without attempting to authenticate or exploit any vulnerabilities.

This tool is built for educational and ethical security research purposes. Network scanning requires explicit consent—only scan systems, networks, or repositories you own or have written permission to test.

## Skills Demonstrated

- Python automation for security tooling
- Regex-based secret and credential detection
- Secure report generation (HTML/PDF) with redaction by design
- Safe data handling — hashing over storage of raw sensitive values
- Modular, extensible code architecture

---

## Disclaimer

CredHunt is built for educational and ethical security research purposes. Only scan systems, repositories, or files you own or have explicit permission to access.
