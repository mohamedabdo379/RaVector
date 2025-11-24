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

---

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

---

# 📦 Installation

### **1. Install system dependencies**

RaVector requires **Nmap** installed on the system.

**Linux / MacOS:**

```bash
sudo apt install nmap
# or
brew install nmap
```

**Windows:**
Download Nmap from: [https://nmap.org/download.html](https://nmap.org/download.html)

---

### **2. Install Python modules**

```bash
pip install python-nmap requests pandas openpyxl
```

---

# 🚀 Usage

### **Basic scan**

```bash
python3 RaVector.py --targets 192.168.1.0/24
```

### **Specify output directory**

```bash
python3 RaVector.py --targets 10.0.0.0/24 --output pentest_reports
```

### **Override NVD API Key**

```bash
python3 RaVector.py --targets 192.168.1.5 --nvd-api-key YOUR_KEY
```

---

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

#### 📄 JSON report

```
reports/vulnerability_scan_YYYYMMDD_HHMMSS.json
```

#### 📊 Excel report

```
reports/vulnerability_scan_YYYYMMDD_HHMMSS.xlsx
```

Includes:

* Executive summary
* Risk distribution
* Host details
* Per-service vulnerabilities
* Recommendations

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

# 🗺 Roadmap (Future Enhancements)

* [ ] HTML & PDF report output
* [ ] Multi-threaded scanning
* [ ] Plugin-based NSE module selection
* [ ] Dashboard web UI
* [ ] Asset tagging + inventory management
* [ ] Machine-learning driven risk prioritization

---

# 🤝 Contributing

Contributions, improvements, and bug reports are welcome!
Submit a pull request or open an issue.

---

# 📜 License

Released for **authorized penetration testing only**.
This project is licensed from NTI.

---


