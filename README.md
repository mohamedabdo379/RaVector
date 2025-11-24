**Here is your full, professional, ready-to-use documentation** for your tool.  
I’ve named it **VulnForge** (you can change the name anytime — it sounds strong and professional for a commercial pentest recon + vuln scanner).

Everything is written in clean **Markdown** — perfect for GitHub, GitLab, ReadTheDocs, or your future product website.

---

# VulnForge – Automated Reconnaissance & Vulnerability Scanner

[![Version](https://img.shields.io/badge/version-1.0-brightgreen)]() [![Python](https://img.shields.io/badge/python-3.8%2B-blue)]() [![License](https://img.shields.io/badge/license-Commercial-red)]()

**Fast • Reliable • NVD-integrated • Pentester-focused**

VulnForge is a powerful, all-in-one reconnaissance and vulnerability scanning tool designed specifically for professional penetration testers and red teams. It combines host discovery, precise service enumeration, NSE vulnerability scripts, and real-time CVE lookup via the official NVD API — all in a single Python script with beautiful JSON + Excel reporting.

Save hours on every assessment. Sell confidence.

---

## Features

- **Host Discovery** (`-sn` ping sweep) on networks/ranges
- **Smart Port & Service Scanning** (root → SYN scan, non-root → TCP connect)
- **Accurate Version Detection** (`--version-intensity 5`)
- **Built-in NSE Vulnerability Scripts** (`vuln`, `http-vuln-*`, `smb-vuln-*`, etc.)
- **Real-time CVE Lookup** using official **NVD 2.0 API**
- **Intelligent Software Mapping** (Apache, Nginx, OpenSSH, IIS, MySQL, PostgreSQL, etc.)
- **Automatic Risk Scoring** (Critical / High / Medium / Low)
- **Professional Reports**: JSON + Excel (with Executive Summary sheet)
- **Rate-limit aware** NVD client with retry + caching
- Single-file deployment – no complex setup

---

## Screenshots

*(You can replace these with real ones later)*

```markdown
![Scan in progress](https://via.placeholder.com/800x400?text=Scan+Output+Example)
![Excel Report](https://via.placeholder.com/800x500?text=Excel+Report+with+Executive+Summary)
```

---

## Installation

### Requirements

```bash
Python 3.8+
nmap (the actual binary must be installed and in PATH)
```

### Install system dependency (Nmap)

**Linux:**
```bash
sudo apt install nmap -y        # Debian/Ubuntu
sudo yum install nmap -y        # CentOS/RHEL
```

**macOS:**
```bash
brew install nmap
```

**Windows:** Download from https://nmap.org/download.html

### Install Python dependencies

```bash
pip install python-nmap requests pandas openpyxl
```

### (Optional) Set your own NVD API key (recommended for production/sale)

```bash
export NVD_API_KEY="your-real-nvd-key-here"
```

> A free NVD API key can be obtained here: https://nvd.nist.gov/developers/request-an-api-key  
> (The tool ships with a working default key for demo purposes only)

---

## Usage

```bash
python3 VulnForge.py --targets <target> [options]
```

### Examples

```bash
# Scan a single host
python3 VulnForge.py -t 192.168.1.100

# Scan an entire subnet (auto host discovery)
python3 VulnForge.py -t 192.168.10.0/24

# Multiple targets
python3 VulnForge.py -t 10.0.0.5,10.0.0.10-10.0.0.20,192.168.1.0/24

# Custom output directory + your own NVD key
python3 VulnForge.py -t 172.16.0.0/16 -o my_client_reports --nvd-api-key "abcd1234-..."
```

### Command-line Options

| Option             | Description                                    | Default         |
|-------------------|------------------------------------------------|-----------------|
| `--targets`, `-t` | Targets (IP, range, CIDR, comma-separated)     | **Required**    |
| `--output`, `-o`  | Output directory for reports                   | `reports`       |
| `--nvd-api-key`   | Override NVD API key                           | Uses env → default |

---

## Output & Reports

After completion, two files are generated in the output directory:

1. `vulnerability_scan_YYYYMMDD_HHMMSS.json` – Full structured data (great for automation)
2. `vulnerability_scan_YYYYMMDD_HHMMSS.xlsx` – Human-readable Excel with two sheets:
   - **Vulnerabilities** – Full list with CVE, CVSS, port, service
   - **Executive_Summary** – High-level stats and recommendations (perfect for client delivery)

---

## Ethical & Legal Disclaimer (MANDATORY FOR COMMERCIAL TOOLS)

> VulnForge is a security research and authorized penetration testing tool.  
> You **MUST** have explicit written permission from the system owner before scanning any target that you do not own or are not authorized to test.  
> Unauthorized scanning is illegal in most jurisdictions.  
> The authors and distributors assume **no liability** for misuse of this software.

Include this in your EULA when selling.

---

## Roadmap (Future Premium Features)

- [ ] Web GUI dashboard (Flask/FastAPI)
- [ ] Scheduled scans & email reports
- [ ] Exploit suggestion module (Exploit-DB + Metasploit integration)
- [ ] Custom NSE script packs
- [ ] Team collaboration & client portal
- [ ] Commercial license with support & updates

---

## Frequently Asked Questions

**Q: Why is Excel report missing?**  
A: Install pandas & openpyxl: `pip install pandas openpyxl`

**Q: NVD requests are failing (403)**  
A: The default API key has rate limits. Get your own free key from NIST and use `--nvd-api-key` or `NVD_API_KEY` env var.

**Q: Can I run this on Windows?**  
A: Yes! Just install Nmap for Windows and run with Python.

**Q: Is it safe to share the script with clients?**  
A: Yes — but remove or replace the hard-coded default API key before commercial distribution.

---

## License

**Commercial License** – You are free to sell, rebrand, and distribute VulnForge under your own brand.  
Source code redistribution requires purchasing a commercial license (contact below).

---

## Contact & Support

For licensing, custom development, or white-label versions:

**Email:** [mohamedabdofares4@gmail.com]  
**Website:**  (coming soon)

Made with ❤️ for the offensive security community.

---

**You now have a complete, professional, and sell-ready documentation!**

Just save this as `README.md` in your project root, create a `reports/` folder, and you’re ready to impress clients or post on GitHub/HackerOne/any marketplace.

Want me to:
- Generate a logo?
- Create a one-page sales landing page (HTML)?
- Package it as a PyPI wheel?
- Add a commercial license template?

Just say the word — I’ve got you covered! 🚀