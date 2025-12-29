# **RaVector – Advanced Automated Vulnerability Scanner**

*A modular, extensible reconnaissance and vulnerability-analysis framework for authorized penetration testing.*

```
8888888b.           888     888                   888                    
888   Y88b          888     888                   888                    
888    888          888     888                   888                    
888   d88P  8888b.  Y88b   d88P  .d88b.   .d8888b 888888 .d88b.  888d888 
8888888P"      "88b  Y88b d88P  d8P  Y8b d88P"    888   d88""88b 888P"   
888 T88b   .d888888   Y88o88P   88888888 888      888   888  888 888     
888  T88b  888  888    Y888P    Y8b.     Y88b.    Y88b. Y88..88P 888     
888   T88b "Y888888     Y8P      "Y8888   "Y8888P  "Y888 "Y88P"  888                                                             
                                                                         
                                                                          v1.0
```

## ⚠️ **Legal & Ethical Notice**

**RaVector is designed *exclusively* for licensed penetration testers, SOC teams, and researchers performing authorized security assessments.**
Using this tool **against systems you do not own or have explicit permission to test is illegal and strictly prohibited.**

By using RaVector, you agree that you are conducting **authorized and lawful** testing only.

---

# 🔥 About RaVector

**RaVector** is a unified vulnerability-scanning engine that merges host discovery, service enumeration, Nmap-based NSE scanning, and live CVE enrichment using NVD v2.0.
It automates early-stage reconnaissance and produces polished **JSON** and **Excel** reports suitable for penetration tests and audit deliverables.

### ✨ Key Features

* 🔍 **Network discovery** (Nmap -sn)
* 🧩 **Service & version enumeration** with automatic SYN/TCP fallback
* 🧪 **NSE vulnerability scripts**
* 🌐 **CVE lookup using the NVD 2.0 API**
* 📊 **JSON & Excel reporting**
* 🧠 **Risk scoring using CVSS**
* ⚡ **Automatic rate-limiting & retry logic for NVD requests**
* 🎯 **Modules combined into one fully orchestrated scanning engine**

---

# 🏗 Architecture

```
                   ┌────────────────────────┐
                   │        RaVector        │
                   │    (Orchestrator       │
                   └─────────────┬──────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
┌───────────────┐       ┌─────────────────┐      ┌────────────────┐
│ Host Discovery│       │ Service Enum    │      │   NSE Scripts  │
│   (nmap -sn)  │       │ (ports, banners)│      │ (vuln, smb,…)  │
└───────────────┘       └─────────────────┘      └────────────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ CVE Integration  │
                        │ (NVD API v2.0)   │
                        └─────────┬────────┘
                                  │
                                  ▼
                        ┌──────────────────┐
                        │ Report Generator │
                        │ JSON / Excel     │
                        └──────────────────┘
```

# 🎯 What RaVector Does

### 1. **Host Discovery**

Uses Nmap `-sn` to identify live hosts.

### 2. **Service Enumeration**

* Detects open ports
* Extracts service name, product, and version
* Auto-uses `-sS` if running as root

### 3. **NSE Vulnerability Scripts**

Runs modules like:

* `vuln`
* `http-vuln-*`
* `smb-vuln-*`
* `ssh-auth-methods`

### 4. **CVE Enrichment**

Queries:

```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

Extracts:

* CVE ID
* English description
* CVSS v2 / v3 score
* Associates the CVE with:

  * host
  * port
  * protocol
  * service

### 5. **Report Generation**

Produces **2 outputs:**

#### 📄 JSON and PDF report

```
reports/vulnerability_scan_YYYYMMDD_HHMMSS.json
reports/vulnerability_scan_YYYYMMDD_HHMMSS.pdf
```

---

# 📝 Example Output (JSON)

```json
{
  "scan_metadata": {
    "timestamp": "2025-01-17T22:11:36",
    "scanner_version": "MergedScanner 1.0",
    "targets_scanned": 3
  },
  "executive_summary": {
    "total_hosts_scanned": 3,
    "total_vulnerabilities_found": 12
  }
}
```

---

# 🧩 Project Structure

```
RaVector.py
└── BasicVulnerabilityScanner
    ├── host_discovery()
    ├── service_enumeration()
    └── run_nse_scripts()

└── CVEIntegration
    ├── search_cve_online()
    ├── analyze_service_vulnerabilities()
    └── extract_software_info()

└── ReportGenerator
    ├── generate_json_report()
    ├── generate_excel_report()
    └── risk & summary helpers
```

---

# 🔒 Security Notes

* The NVD API key is **configurable**, and a default placeholder exists for convenience.
* Rate limits are handled automatically via exponential backoff.
* No scanning occurs without explicit user execution.


---

# 🗺 Roadmap (Future Enhancements)

* [ ] HTML & PDF report output
* [ ] Multi-threaded scanning
* [ ] Plugin-based NSE module selection
* [ ] Dashboard web UI
* [ ] Asset tagging + inventory management
* [ ] Machine-learning driven risk prioritization
---

# 📦 Installation

This guide explains how to set up a clean environment and install all required dependencies to run **RaVector** successfully.

---

### ✅ Prerequisites

Make sure your system meets the following requirements:

* **Operating System:** Linux, macOS, or Windows (WSL recommended)
* **Python Version:** Python **3.8+**
* **Privileges:** Administrator / root access (required for some scans)
* **Internet Connection:** Required for NVD API and email reporting

Check Python version:

```bash
python3 --version
```

---

### 📦 Step 1: Install Nmap

RaVector uses **Nmap** as its scanning engine.

**Linux (Ubuntu/Debian):**

```bash
sudo apt update
sudo apt install nmap
```

**macOS (Homebrew):**

```bash
brew install nmap
```

**Windows:**

* Download and install Nmap from: [https://nmap.org/download.html](https://nmap.org/download.html)
* Ensure `nmap` is added to your system PATH

Verify installation:

```bash
nmap --version
```

---

### 📥 Step 2: Clone the Repository

```bash
git clone https://github.com/yourusername/RaVector.git
cd RaVector
```

---

### 🧪 Step 3: Create a Virtual Environment (Recommended)

Using a virtual environment is strongly recommended to avoid dependency conflicts.

```bash
python3 -m venv venv
```

Activate the virtual environment:

**Linux / macOS:**

```bash
source venv/bin/activate
```

**Windows (PowerShell):**

```powershell
venv\Scripts\Activate.ps1
```

You should see `(venv)` in your terminal once activated.

---

### 🔄 Step 4: Upgrade pip

```bash
pip install --upgrade pip
```

---

### 📚 Step 5: Install Python Dependencies

Install all libraries required by RaVector:

```bash
pip install python-nmap requests pandas openpyxl apscheduler pytz fpdf pyfiglet colorama 
```

These libraries are used for:

* Network scanning
* CVE intelligence retrieval
* Report generation
* Task scheduling
* CLI enhancements

---

### 🔐 Step 6: Configure NVD API Key (Optional but Recommended)

To enable CVE lookups from the National Vulnerability Database:

```bash
export NVD_API_KEY="your_nvd_api_key"
```

Request an API key from:
[https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

---

### ▶️ Step 7: Verify Installation

Run the following command to confirm successful setup:

```bash
python3 RaVector.py --help
```

If the help menu appears, RaVector is ready to use ✅

---

### 🛑 Deactivate Virtual Environment (Optional)

```bash
deactivate
```

### **Windows:**
Download Nmap from: [https://nmap.org/download.html](https://nmap.org/download.html)

---

## 🧭 Usage & CLI Navigation

RaVector operates through an **interactive command-line interface (CLI)** designed to be intuitive, fast, and efficient for penetration testers.
Once launched, users interact with RaVector using structured commands grouped by purpose.

![RaVector Termenal](https://github.com/user-attachments/assets/f073cc30-b2b6-4935-af60-9f0407140cd8)

When the CLI starts, you will see the RaVector banner and the prompt:
```
RaVector >>
```

From here, you can configure settings, run scans, schedule jobs, and access exploitation assistance.

---

### 🛠 Configuration Commands

These commands allow you to define default values that RaVector will use during scans.

```
set default targets <value>
```

* Sets the default scan targets
* Accepts a single IP, multiple IPs, or CIDR ranges
* Example:

```bash
set default targets 192.168.1.0/24
```

```
set default output <path>
```

* Sets the default directory where reports will be saved
* Supports TAB auto-completion for paths
* Example:

```bash
set default output reports/
```

```
set default nvd_api_key <key>
```

* Sets the default NVD API key for CVE lookups
* Example:

```bash
set default nvd_api_key YOUR_API_KEY_HERE
```

---

### ⚡ Immediate Scan Commands

These commands allow you to start scans instantly.

```
scan now
```

* Starts a scan using the currently configured default settings
* Automatically performs:

  * Host discovery
  * Service enumeration
  * CVE mapping
  * Report generation
  * Email delivery

```
scan now targets=<ips> output=<dir>
```

* Runs a scan with temporary overrides
* Does not change saved defaults
* Example:

```bash
scan now targets=10.10.10.5 output=custom_reports/
```

---

### ⏱ Scheduling Commands

RaVector supports scheduled scans using a cron-like format.

```
schedule add <id> <min> <hour> <day> <month> <day-in-week>
```

* Adds a new scheduled scan
* Example (run every day at 02:00):

```bash
schedule add daily_scan 0 2 * * *
```

```
schedule list
```

* Displays all currently scheduled scan jobs

```
schedule remove <id>
```

* Removes a scheduled scan by its ID
* Example:

```bash
schedule remove daily_scan
```

---

### ⚔ Exploitation Menu

```
exploit
```

* Opens the exploitation assistant menu
* Provides exploitation guidance for common services such as:

  * FTP
  * NFS
  * SSH
  * SMB
* Displays recommended tools and starting steps based on detected vulnerabilities

This feature is intended to **guide the pentester**, not perform automatic exploitation.

---

### 📋 General Commands

```
help
```

* Displays the full CLI help menu with all available commands

```
exit
```

* Safely exits the RaVector CLI

---

### 🧠 Typical Workflow Example

1. Set defaults:

```bash
set default targets 192.168.1.0/24
set default output reports/
```

2. Start a scan:

```bash
scan now
```

3. Review the results:

* PDF report is generated
* PDF is automatically emailed to the pentester

4. Use exploitation guidance:

```bash
exploit
```

---

### 📌 Notes

* Most scans require **administrator/root privileges**
* Internet access is required for CVE lookups and email delivery
* Scheduled scans will run automatically even when the user is not present

---


---

# 🛠 Troubleshooting

### **“python-nmap required”**

Install it:

```bash
pip install python-nmap
```

### **Excel export doesn’t work**

Install:

```bash
pip install pandas openpyxl
```

### **403 Forbidden from NVD**

* Your API key may be missing or expired
* Set a new key via:

```bash
export NVD_API_KEY="yourkey"
```
---

# 🤝 Contributing

Contributions, improvements, and bug reports are welcome!
Submit a pull request or open an issue.

---

# 📜 License

Released for **authorized penetration testing only**.
This project is licensed from NTI.

---










