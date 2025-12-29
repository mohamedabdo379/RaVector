#!/usr/bin/env python3
"""
Merged: RaVector / S.A.V.R. combined interactive shell + scanner
References: original components from uploaded files. See file citations in assistant reply.
"""
import os
import json
import threading
import time
import argparse
from datetime import datetime
from time import sleep

# --- Optional / Safe imports with user-friendly messages ---
try:
    import nmap
except Exception:
    nmap = None

try:
    import requests
except Exception:
    requests = None

try:
    import pandas as pd
except Exception:
    pd = None

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except Exception:
    FPDF_AVAILABLE = False

# UI / scheduler libs
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.executors.pool import ThreadPoolExecutor
except ModuleNotFoundError:
    print("[!] Missing library 'apscheduler'. Install it with: pip install apscheduler")
    exit(1)

try:
    from pytz import timezone
except ModuleNotFoundError:
    print("[!] Missing library 'pytz'. Install it with: pip install pytz")
    exit(1)

try:
    import pyfiglet
except ModuleNotFoundError:
    print("[!] Missing library 'pyfiglet'. Install it with: pip install pyfiglet")
    exit(1)

try:
    from colorama import Fore, Style
except ModuleNotFoundError:
    print("[!] Missing library 'colorama'. Install it with: pip install colorama")
    class Dummy:
        def __getattr__(self, name): return ""
    Fore = Style = Dummy()

# -----------------------------
# ---- scanner code (from RaVector.py) ----
# -----------------------------

# helper to sanitize text for PDF
def clean_text(text):
    if not text:
        return ""
    replacements = {
        '\u2013': '-', '\u2014': '-', '\u2018': "'", '\u2019': "'",
        '\u201c': '"', '\u201d': '"', '\uff1a': ':', '\u2022': '*',
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)
    return text.encode('latin-1', 'replace').decode('latin-1')

def get_remediation_action(cwe_id):
    remediations = {
        'CWE-79':  "Input Validation: Sanitize all user input. Implement Content Security Policy (CSP).",
        'CWE-89':  "SQL Injection: Use parameterized queries (prepared statements). Avoid string concatenation in SQL.",
        'CWE-78':  "Command Injection: Avoid system calls with user input. Use library functions instead of shell commands.",
        'CWE-787': "Memory Safety: Update software to latest version. Use memory-safe languages if custom code.",
        'CWE-416': "Memory Safety: Ensure proper pointer handling. Apply vendor patches immediately.",
        'CWE-22':  "Path Traversal: Validate filenames. Use strict allowlists for file paths.",
        'CWE-434': "File Upload: Validate file types/extensions. Store uploads outside the web root.",
        'CWE-306': "Auth: Implement multi-factor authentication (MFA) and strict access controls.",
        'CWE-502': "Deserialization: Do not deserialize untrusted data. Use safer data formats like JSON.",
        'CWE-119': "Buffer Overflow: Update software. Enable compiler security features (ASLR, DEP).",
        'CWE-200': "Info Disclosure: Disable verbose error messages. Review permission settings."
    }
    return remediations.get(cwe_id, "General: Update to the latest vendor version and check configuration.")

class BasicVulnerabilityScanner:
    def __init__(self):
        if nmap is None:
            raise RuntimeError("python-nmap is required. Install with: pip install python-nmap")
        self.nm = nmap.PortScanner()

    def host_discovery(self, target_range):
        print(f"[+] Scanning network range: {target_range}")
        try:
            self.nm.scan(hosts=target_range, arguments='-sn')
            active_hosts = []
            for host in self.nm.all_hosts():
                try:
                    if self.nm[host].state() == 'up':
                        active_hosts.append(host)
                        print(f"  [+] Found active host: {host}")
                except Exception:
                    continue
            return active_hosts
        except Exception as e:
            print(f"[-] Host discovery failed: {e}")
            return []

    def service_enumeration(self, target_host):
        print(f"[+] Scanning services on: {target_host}")
        try:
            try:
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    scan_args = '-sV -sS -T4 --version-intensity 5'
                else:
                    scan_args = '-sV -sT -T4 --version-intensity 5'
            except Exception:
                scan_args = '-sV -T4 --version-intensity 5'

            self.nm.scan(hosts=target_host, arguments=scan_args)

            host_info = {
                'hostname': target_host,
                'status': self.nm[target_host].state() if target_host in self.nm.all_hosts() else 'unknown',
                'protocols': {},
                'vulnerabilities': []
            }

            if target_host not in self.nm.all_hosts():
                return host_info

            for proto in self.nm[target_host].all_protocols():
                host_info['protocols'][proto] = {}
                ports = list(self.nm[target_host][proto].keys())
                for port in ports:
                    port_info = self.nm[target_host][proto][port]
                    host_info['protocols'][proto][port] = {
                        'state': port_info.get('state', 'unknown'),
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', '')
                    }
                    print(f"    [+] Port {port}/{proto}: {port_info.get('name','?')} - {port_info.get('version','?')}")

            return host_info
        except Exception as e:
            print(f"[-] Service enumeration failed for {target_host}: {e}")
            return None

    def run_nse_scripts(self, target_host, nse_scripts=None):
        print(f"[+] Running NSE scripts on: {target_host}")
        if nse_scripts is None:
            nse_scripts = ['default', 'http-vuln-*', 'ssh-auth-methods', 'smb-vuln-*']

        try:
            nse_args = f'-sV --script {",".join(nse_scripts)}'
            self.nm.scan(hosts=target_host, arguments=nse_args)

            vulnerabilities = []
            if target_host in self.nm.all_hosts() and 'script' in self.nm[target_host]:
                for script_name, script_output in self.nm[target_host]['script'].items():
                    out_str = str(script_output)
                    if any(k in out_str.upper() for k in ['VULNERABLE', 'ERROR', 'WARNING']):
                        vulnerabilities.append({
                            'script': script_name,
                            'output': script_output,
                            'risk': 'Medium',
                            'cve_id': 'NSE-SCRIPT',
                            'cvss_score': 'N/A',
                            'cwe_id': 'N/A',
                            'action': 'Review script output manually.',
                            'remediation_links': []
                        })
                        print(f"    [!] Vulnerability found by script: {script_name}")

            return vulnerabilities
        except Exception as e:
            print(f"[-] NSE scanning failed: {e}")
            return []

class CVEIntegration:
    def __init__(self, api_key=None, user_agent="MergedScanner/1.0"):
        if requests is None:
            raise RuntimeError("requests is required. Install with: pip install requests")

        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        default_key = "43b82294-7a9d-4487-af55-983fcda7fbf6"
        self.api_key = api_key or os.environ.get("NVD_API_KEY") or default_key
        self.user_agent = user_agent
        self.cve_cache = {}

    def extract_software_info(self, service_info):
        software_mapping = {
            'apache': 'apache http server',
            'nginx': 'nginx',
            'microsoft-iis': 'internet information services',
            'openssh': 'openssh',
            'mysql': 'mysql',
            'postgresql': 'postgresql'
        }
        product = (service_info.get('product') or '').lower()
        version = service_info.get('version') or ''
        for key, value in software_mapping.items():
            if key in product:
                return value, version
        return service_info.get('service', '').lower(), version

    def _do_request_with_retries(self, params, max_retries=3, backoff_factor=1.0):
        headers = {"User-Agent": self.user_agent}
        if self.api_key:
            headers["apiKey"] = self.api_key

        attempt = 0
        while attempt <= max_retries:
            try:
                resp = requests.get(self.nvd_api_url, params=params, headers=headers, timeout=15)
            except Exception:
                attempt += 1
                sleep(backoff_factor * attempt)
                continue

            if resp.status_code == 200:
                return resp
            if resp.status_code in (429, 502, 503, 504):
                attempt += 1
                sleep(backoff_factor * (2 ** attempt))
                continue
            return resp
        return None

    def search_cve_online(self, software_name, version):
        if not software_name: return []
        cache_key = f"{software_name}_{version}"
        if cache_key in self.cve_cache: return self.cve_cache[cache_key]
        if not self.api_key: return []

        params = {"keywordSearch": f"{software_name} {version}".strip(), "resultsPerPage": 10}
        resp = self._do_request_with_retries(params)

        if not resp or resp.status_code != 200:
            return []

        try:
            items = resp.json().get("vulnerabilities", [])
        except:
            return []

        vulnerabilities = []
        for item in items:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")

            description = "No description available."
            for d in cve_obj.get("descriptions", []):
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break

            base_score = "Unknown"
            metrics = cve_obj.get("metrics", {})
            if "cvssMetricV31" in metrics:
                base_score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "Unknown")
            elif "cvssMetricV2" in metrics:
                base_score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", "Unknown")

            cwe_id = "Unknown"
            weaknesses = cve_obj.get("weaknesses", [])
            if weaknesses:
                desc_list = weaknesses[0].get("description", [])
                if desc_list:
                    cwe_id = desc_list[0].get("value", "Unknown")

            references = [ref.get('url') for ref in cve_obj.get('references', [])]

            action_plan = get_remediation_action(cwe_id)

            vulnerabilities.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": base_score,
                "cwe_id": cwe_id,
                "software": software_name,
                "version": version,
                "action": action_plan,
                "remediation_links": references
            })

        self.cve_cache[cache_key] = vulnerabilities
        return vulnerabilities

    def analyze_service_vulnerabilities(self, service_data):
        all_vulnerabilities = []
        for proto, ports in service_data.get('protocols', {}).items():
            for port, service_info in ports.items():
                if service_info.get('state') == 'open':
                    software, version = self.extract_software_info(service_info)
                    if software:
                        print(f"[+] Checking CVEs for: {software} {version}")
                        cves = self.search_cve_online(software, version)
                        for cve in cves:
                            cve.update({'port': port, 'protocol': proto, 'service': service_info.get('service')})
                            all_vulnerabilities.append(cve)
                        sleep(0.6)
        return all_vulnerabilities

# --- STANDARD PDFReport Class (Fixed Font) ---
if FPDF_AVAILABLE:
    class PDFReport(FPDF):
        def header(self):
            self.set_font('Arial', 'B', 15)
            self.cell(0, 10, 'S.A.V.R. Vulnerability Scan Report', 0, 1, 'C')
            self.ln(5)

        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

        def chapter_title(self, title):
            self.set_font('Arial', 'B', 12)
            self.set_fill_color(200, 220, 255)
            self.cell(0, 10, title, 0, 1, 'L', 1)
            self.ln(4)

        def chapter_body(self, body):
            self.set_font('Arial', '', 10)
            self.multi_cell(0, 10, clean_text(body)) # Use clean_text here
            self.ln()

class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _determine_risk_level(self, cvss_score):
        try:
            score = float(cvss_score)
            if score >= 9.0: return 'Critical'
            elif score >= 7.0: return 'High'
            elif score >= 4.0: return 'Medium'
            elif score > 0: return 'Low'
            return 'Info'
        except:
            return 'Info'

    def _calculate_risk_stats(self, scan_data):
        stats = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for host in scan_data.get('hosts', []):
            for vuln in host.get('vulnerabilities', []):
                risk = self._determine_risk_level(vuln.get('cvss_score'))
                stats[risk] += 1
        return stats

    def generate_json_report(self, scan_data):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(self.output_dir, f'scan_{timestamp}.json')
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_data, f, indent=2)
        print(f"[+] JSON report generated: {filepath}")
        return filepath

    def generate_pdf_report(self, scan_data):
        if not FPDF_AVAILABLE:
            return None
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(self.output_dir, f'S.A.V.R_Report_{timestamp}.pdf')
        
        pdf = PDFReport()
        pdf.add_page()
        
        # --- Executive Summary ---
        pdf.chapter_title("Executive Summary")
        stats = self._calculate_risk_stats(scan_data)
        total_vulns = sum(stats.values())
        duration = scan_data.get('scan_duration', 'Unknown')
        
        summary_text = (
            f"Scan completed on: {scan_data.get('scan_end')}\n"
            f"Duration: {duration}\n"
            f"Total Hosts Scanned: {len(scan_data.get('hosts', []))}\n"
            f"Total Vulnerabilities Found: {total_vulns}\n"
        )
        pdf.chapter_body(summary_text)
        
        # Risk Table
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(40, 10, 'Risk Level', 1)
        pdf.cell(40, 10, 'Count', 1)
        pdf.ln()
        
        pdf.set_font('Arial', '', 10)
        for level, count in stats.items():
            if count > 0:
                if level == 'Critical': pdf.set_text_color(255, 0, 0)
                elif level == 'High': pdf.set_text_color(200, 100, 0)
                elif level == 'Medium': pdf.set_text_color(255, 165, 0)
                else: pdf.set_text_color(0, 0, 0)
                pdf.cell(40, 10, level, 1)
                pdf.cell(40, 10, str(count), 1)
                pdf.ln()
        
        pdf.set_text_color(0, 0, 0)
        pdf.ln(10)

        # --- Detailed Findings ---
        pdf.add_page()
        pdf.chapter_title("Detailed Findings")
        
        COL_WIDTHS = [30, 35, 20, 105] 
        LINE_HEIGHT = 4# <--- CHANGE 1: Adjusted line height for compactness
        
        remediation_data = {} 

        for host in scan_data.get('hosts', []):
            hostname = host.get('hostname')
            vulns = host.get('vulnerabilities', [])
            
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 10, f"Host: {hostname} ({host.get('status')})", 0, 1)
            
            if not vulns:
                pdf.set_font('Arial', 'I', 10)
                pdf.cell(0, 10, "No vulnerabilities found.", 0, 1)
                pdf.ln(5)
                continue
            
            # Header
            pdf.set_fill_color(230, 230, 230)
            pdf.set_font('Arial', 'B', 9)
            pdf.cell(COL_WIDTHS[0], 8, "Service", 1, 0, 'C', 1)
            pdf.cell(COL_WIDTHS[1], 8, "CVE ID", 1, 0, 'C', 1)
            pdf.cell(COL_WIDTHS[2], 8, "Risk", 1, 0, 'C', 1)
            pdf.cell(COL_WIDTHS[3], 8, "Description", 1, 0, 'C', 1)
            pdf.ln()
            
            pdf.set_font('Arial', '', 8)
            
            # --- Table Data Loop ---
            for v in vulns:
                service = clean_text(f"{v.get('service', 'unk')}:{v.get('port', 'unk')}")
                cve = clean_text(v.get('cve_id', 'N/A'))
                score = v.get('cvss_score', '0')
                risk = self._determine_risk_level(score)
                # Ensure description is clean and sanitized
                desc = clean_text(v.get('description', 'No description').replace('\n', ' '))

                # Calculate Row Height
                temp_pdf = PDFReport()
                temp_pdf.set_font('Arial', '', 8)
                temp_pdf.add_page()
                temp_pdf.multi_cell(COL_WIDTHS[3], LINE_HEIGHT, desc, 0, 'L')
                
                # Calculate the height based on multi_cell output position
                required_height = temp_pdf.get_y() - 10 
                # Cell height must be at least one LINE_HEIGHT
                cell_height = max(LINE_HEIGHT, required_height)
                
                # Page Break Check
                if pdf.get_y() + cell_height > pdf.page_break_trigger:
                    pdf.add_page()
                    pdf.set_fill_color(230, 230, 230)
                    pdf.set_font('Arial', 'B', 9)
                    pdf.cell(COL_WIDTHS[0], 8, "Service", 1, 0, 'C', 1)
                    pdf.cell(COL_WIDTHS[1], 8, "CVE ID", 1, 0, 'C', 1)
                    pdf.cell(COL_WIDTHS[2], 8, "Risk", 1, 0, 'C', 1)
                    pdf.cell(COL_WIDTHS[3], 8, "Description", 1, 0, 'C', 1)
                    pdf.ln()
                    pdf.set_font('Arial', '', 8)
                    
                x_start = pdf.get_x()
                y_start = pdf.get_y()
                
                # --- Drawing Fixed Cells (Using calculated height) ---
                
                # Service Cell (Draws full border '1')
                pdf.cell(COL_WIDTHS[0], cell_height, service, 1, 0, 'L')
                
                # CVE ID Cell (Draws full border '1')
                pdf.cell(COL_WIDTHS[1], cell_height, cve, 1, 0, 'L') 
                
                if risk in ['Critical', 'High']: 
                    pdf.set_text_color(200, 0, 0)
                    remediation_data[f"{hostname} - {cve}"] = v 
                elif risk == 'Medium': 
                    pdf.set_text_color(255, 140, 0)
                
                # Risk Cell (Draws full border '1')
                pdf.cell(COL_WIDTHS[2], cell_height, risk, 1, 0, 'C')
                pdf.set_text_color(0, 0, 0)

                # --- Drawing Multi-Cell (Description) ---
                
                # Set coordinates for multi-cell
                pdf.set_xy(x_start + COL_WIDTHS[0] + COL_WIDTHS[1] + COL_WIDTHS[2], y_start) 
                
                # Draw Description Cell (Draws full border '1', completes the row)
                pdf.multi_cell(COL_WIDTHS[3], LINE_HEIGHT, desc, 1, 'L', fill=False) 
                
                # Reset cursor position for the next row
                pdf.set_y(y_start + cell_height)
            
            pdf.ln(10)
        
        # --- Remediation Section (Actionable) ---
        if remediation_data:
            pdf.add_page()
            pdf.chapter_title("Remediation Guidance (Critical & High)")
            pdf.set_font('Arial', '', 10)
            
            for finding, v_obj in remediation_data.items():
                pdf.set_font('Arial', 'B', 10)
                pdf.set_text_color(200, 0, 0)
                pdf.multi_cell(0, 5, clean_text(f"Finding: {finding} (CWE: {v_obj.get('cwe_id')})"), 0, 'L')
                
                pdf.set_text_color(0, 0, 0)
                pdf.set_font('Arial', '', 9)
                pdf.multi_cell(0, 5, clean_text(f"Recommendation: {v_obj.get('action')}"), 0, 'L')
                
                links = v_obj.get('remediation_links', [])
                if links:
                    pdf.ln(2)
                    pdf.set_font('Arial', 'I', 9)
                    pdf.multi_cell(0, 5, "Official Vendor References:", 0, 'L')
                    pdf.set_text_color(0, 0, 255)
                    for link in links[:3]: # Limit to top 3 links to save space
                        pdf.multi_cell(0, 5, clean_text(f"  -> {link}"), 0, 'L')
                    pdf.set_text_color(0, 0, 0)
                pdf.ln(5)

        try:
            pdf.output(filepath, 'F')
        except Exception as e:
            print(f"[-] ERROR saving PDF file to {filepath}: {e}")
            return None

        print(f"[+] PDF report generated: {filepath}")
        return filepath


def orchestrate_scan(targets, output_dir, nvd_api_key=None):
    start_time = time.time()
    cve_checker = CVEIntegration(api_key=nvd_api_key)
    scanner = BasicVulnerabilityScanner()
    reporter = ReportGenerator(output_dir=output_dir)
    scan_data = {'hosts': [], 'scan_start': datetime.now().isoformat()}
    targets_list = [t.strip() for t in targets.split(',') if t.strip()]
    discovery_targets = targets_list
    final_targets = []
    for t in discovery_targets:
        if '/' in t or '-' in t:
            final_targets.extend(scanner.host_discovery(t))
        else:
            final_targets.append(t)
    final_targets = list(set(final_targets))
    for host in final_targets:
        svc = scanner.service_enumeration(host)
        if svc:
            nse_vulns = scanner.run_nse_scripts(host)
            cve_vulns = cve_checker.analyze_service_vulnerabilities(svc)
            svc['vulnerabilities'] = nse_vulns + cve_vulns
            scan_data['hosts'].append(svc)
    scan_data['scan_end'] = datetime.now().isoformat()
    scan_data['scan_duration'] = f"{time.time() - start_time:.1f}s"
    results = {}
    results['json'] = reporter.generate_json_report(scan_data)
    results['pdf'] = reporter.generate_pdf_report(scan_data)
    return results

# -----------------------------
# ---- ScanCoreShell with Tab Completion ----
# -----------------------------
import shlex

try:
    import readline
except Exception:
    # On Windows the user might have pyreadline
    try:
        import pyreadline as readline  # type: ignore
    except Exception:
        readline = None

# ======= IMPORT EXPLOIT MODULE FROM Exploitation.py =======
import importlib.util
import os

EXP_PATH = os.path.join(os.path.dirname(__file__), "Exploitation.py")
spec = importlib.util.spec_from_file_location("exploit_framework", EXP_PATH)
exploit_framework = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exploit_framework)

# ======= MENU WRAPPER FUNCTION =======
def exploit_menu():
    """Run the exploitation framework menu (from Exploitation.py)."""
    try:
        exploit_framework.main()
    except Exception as e:
        print(f"[ERROR] Exploit menu failed: {e}")


class ScanCoreShell:
    def __init__(self):
        self.config = {
            "targets": "192.168.65.128",
            "output": os.path.expanduser("~/scancore_reports"),
            "nvd_api_key": None
        }
        self._load_config()
        executors = {"default": ThreadPoolExecutor(5)}
        self.scheduler = BackgroundScheduler(executors=executors, timezone=timezone("Africa/Cairo"))
        self.scheduler.start()
        self.banner()
        # setup readline/tab-completion
        self._setup_completion()
        # Show commands immediately so user sees available options on run
        self.help()

    def _get_job_ids(self):
        try:
            return [j.id for j in self.scheduler.get_jobs()]
        except Exception:
            return []

    def _list_dir_matches(self, text):
        # provide filesystem completion for paths (works for relative and absolute)
        if not text:
            text = "."
        dirname = os.path.dirname(text) or "."
        prefix = os.path.basename(text)
        try:
            names = os.listdir(dirname)
        except Exception:
            return []
        matches = []
        for n in names:
            if n.startswith(prefix):
                full = os.path.join(dirname, n)
                if os.path.isdir(full):
                    matches.append(os.path.join(dirname, n) + "/")
                else:
                    matches.append(os.path.join(dirname, n))
        return matches

    def _completion_matches(self, text, state):
        """
        readline completer callback. We build a list of candidates based on current buffer.
        """
        buffer = readline.get_line_buffer() if readline else ""
        try:
            tokens = shlex.split(buffer)
        except Exception:
            tokens = buffer.split()

        # If buffer is empty or first token incomplete -> suggest root commands
        root_cmds = ["help", "scan now", "schedule", "set default", "exit"]
        scan_overrides = ["targets=", "output=", "nvd_api_key="]
        set_default_keys = ["targets", "output", "nvd_api_key"]
        suggestions = []

        # If no tokens yet or we're completing the first token
        if not tokens:
            suggestions = root_cmds
        else:
            # Determine where the cursor is (are we on a new token or editing last token?)
            cur_index = len(tokens) - (0 if buffer.endswith(" ") else 0)
            # We'll make decisions by looking at the first token (command)
            first = tokens[0] if tokens else ""
            # If user typing top-level command (partial)
            if len(tokens) == 1 and not buffer.endswith(" "):
                suggestions = [c for c in root_cmds if c.startswith(first)]
            else:
                # Handle subcommands
                if first == "schedule":
                    # tokens may be e.g. ["schedule", "remove", "jo<TAB>"]
                    if len(tokens) == 2 and not buffer.endswith(" "):
                        # completing second word: add / list / remove
                        subopts = ["add", "list", "remove"]
                        suggestions = [s for s in subopts if s.startswith(tokens[1])]
                    elif len(tokens) >= 2:
                        sub = tokens[1]
                        if sub == "remove":
                            # complete job ids
                            job_ids = self._get_job_ids()
                            last = tokens[-1]
                            suggestions = [jid for jid in job_ids if jid.startswith(last)]
                        elif sub == "add":
                            # for add we expect many numeric/string fields - don't suggest much
                            suggestions = []
                        else:
                            suggestions = []
                elif first == "set" and len(tokens) >= 2:
                    # expected "set default <key> <value>"
                    if len(tokens) == 2:
                        # completing "default"
                        suggestions = ["default"] if "default".startswith(tokens[1]) else []
                    elif len(tokens) == 3:
                        # complete key
                        suggestions = [k for k in set_default_keys if k.startswith(tokens[2])]
                    elif len(tokens) == 4:
                        # complete value; if key is output then suggest filesystem paths
                        key = tokens[2]
                        val_partial = tokens[3]
                        if key == "output":
                            suggestions = self._list_dir_matches(val_partial)
                        else:
                            suggestions = []
                elif first == "scan" and len(tokens) >= 1:
                    # support "scan now" and inline overrides like "scan now output=/tmp"
                    if len(tokens) == 2 and not buffer.endswith(" "):
                        suggestions = ["now"] if "now".startswith(tokens[1]) else []
                    elif len(tokens) >= 2:
                        # completing overrides; offer keys like targets=, output=, nvd_api_key=
                        # figure out current token being edited
                        last = tokens[-1]
                        # If there's an '=' in last, maybe complete a path after output=
                        if last.startswith("output="):
                            path_partial = last.split("=",1)[1]
                            matches = self._list_dir_matches(path_partial)
                            suggestions = [f"output={m}" for m in matches]
                        else:
                            suggestions = [k for k in scan_overrides if k.startswith(last)]
                else:
                    # fallback: suggest filesystem paths if last token looks like a path
                    last = tokens[-1]
                    if last.startswith("/") or last.startswith("."):
                        suggestions = self._list_dir_matches(last)
                    else:
                        # fallback to top-level commands that start with current token
                        suggestions = [c for c in root_cmds if c.startswith(last)]

        # Deduplicate and sort
        suggestions = sorted(list(dict.fromkeys(suggestions)))

        # Store matches for readline to iterate through via state
        if state == 0:
            self._last_matches = suggestions
        try:
            return self._last_matches[state]
        except Exception:
            return None

    def _setup_completion(self):
        if not readline:
            print("[i] Tab completion not available: missing 'readline' or 'pyreadline' package.")
            return
        try:
            # make tab complete
            readline.set_completer(self._completion_matches)
            # Use TAB (not cycle)
            readline.parse_and_bind('tab: complete')
            # Reduce word delimiters so '=' and '/' stay attached for path/value completion
            delimiters = readline.get_completer_delims()
            # remove '=' and '/' from delimiters so completions can include them
            for ch in "=/":
                delimiters = delimiters.replace(ch, '')
            readline.set_completer_delims(delimiters)
        except Exception as e:
            print(f"[i] Could not enable tab completion: {e}")

    # rest of ScanCoreShell methods are the same as before:
    def banner(self):
        ascii_banner = pyfiglet.figlet_format("Ra3Vector", font="bulbhead")
        print(Fore.BLUE + ascii_banner + Style.RESET_ALL)
        print(Fore.GREEN + "Scanner CLI (Cairo Time)" + Style.RESET_ALL)
        

    def _save_config(self):
        try:
            os.makedirs(os.path.dirname(DEFAULT_CONFIG_PATH), exist_ok=True)
            with open(DEFAULT_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"[!] Failed to save config: {e}")

    def _load_config(self):
        try:
            if os.path.exists(DEFAULT_CONFIG_PATH):
                with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load config: {e}")

    def run_scan(self, targets=None, output=None, nvd_api_key=None):
        try:
            targets = targets or self.config["targets"]
            output = output or self.config["output"]
            nvd_api_key = nvd_api_key or self.config.get("nvd_api_key")
            os.makedirs(output, exist_ok=True)
            print(Fore.YELLOW + f"[+] Running scan at {datetime.now().isoformat()} Cairo Time" + Style.RESET_ALL)
            results = orchestrate_scan(targets, output, nvd_api_key=nvd_api_key)
            print(Fore.GREEN + "[-] Scan complete. Reports:" + Style.RESET_ALL)
            print(f"    JSON:  {results.get('json')}")
            print(f"    PDF:   {results.get('pdf')}")
        except Exception as e:
            print(Fore.RED + f"[!] Scan failed: {e}" + Style.RESET_ALL)
            print("    Make sure nmap, requests, and pandas are installed.")

    def add_schedule(self, job_id, minute, hour, day, month, dow):
        try:
            trigger = CronTrigger(minute=minute, hour=hour, day=day, month=month,
                                  day_of_week=dow, timezone=timezone("Africa/Cairo"))
            self.scheduler.add_job(lambda: self.run_scan(), trigger=trigger, id=job_id, replace_existing=True)
            print(Fore.GREEN + f"[+] Scheduled job '{job_id}' added with cron: {minute} {hour} {day} {month} {dow} (Cairo Time)" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to add schedule: {e}" + Style.RESET_ALL)
            print("    Usage: schedule add <id> <min> <hour> <dom> <month> <dow>")

    def list_schedules(self):
        jobs = self.scheduler.get_jobs()
        if not jobs:
            print("[i] No scheduled jobs.")
            return
        for j in jobs:
            print(f" - ID: {j.id} | Next run: {j.next_run_time} | Trigger: {j.trigger}")

    def remove_schedule(self, job_id):
        try:
            self.scheduler.remove_job(job_id)
            print(f"[+] Removed job '{job_id}'.")
        except Exception as e:
            print(f"[!] Failed to remove job '{job_id}': {e}")

    def set_default(self, key, value):
        if key not in ("targets", "output", "nvd_api_key"):
            print("[!] Allowed keys: targets, output, nvd_api_key")
            return
        self.config[key] = value
        self._save_config()
        print(f"[+] Default '{key}' set to: {value}")

    def help(self):
        print(Fore.BLUE + "\n" + "="*50)
        print(" " * 18 + "💡 RaVector CLI Help 💡")
        print("="*50 + Style.RESET_ALL)
        print(Fore.CYAN + "\n[1] ⚙️  Configuration Commands:" + Style.RESET_ALL)
        print(f"  {Fore.GREEN}set default targets <value>{Style.RESET_ALL:<30}- Set default targets (comma or CIDR).")
        print(f"  {Fore.GREEN}set default output <path>{Style.RESET_ALL:<30}- Set default output dir (TAB completes paths).")
        print(f"  {Fore.GREEN}set default nvd_api_key <key>{Style.RESET_ALL:<30}- Set default NVD API key.")
        
        print(Fore.CYAN + "\n[2] 🚀 Immediate Scan Commands:" + Style.RESET_ALL)
        print(f"  {Fore.GREEN}scan now{Style.RESET_ALL:<30}- Start an immediate scan using default settings.")
        print(f"  {Fore.GREEN}scan now targets=<ips> output=<dir>{Style.RESET_ALL:<30}- Run immediate scan with overrides.")

        print(Fore.CYAN + "\n[3] ⏱️  Scheduling Commands:" + Style.RESET_ALL)
        print(f"  {Fore.GREEN}schedule add <id> <min> <hour> <day> <month> <day-in-week>{Style.RESET_ALL:<30}- Add a new scheduled scan (Cron format).")
        print(f"  {Fore.GREEN}schedule list{Style.RESET_ALL:<30}- List all currently scheduled jobs.")
        print(f"  {Fore.GREEN}schedule remove <id>{Style.RESET_ALL:<30}- Remove a scheduled job by its ID.")

        print(Fore.CYAN + "\n[4] 🚪 General Commands:" + Style.RESET_ALL)
        print(f"  {Fore.GREEN}help{Style.RESET_ALL:<30}- Show this help message.")
        print(f"  {Fore.GREEN}exit{Style.RESET_ALL:<30}- Exit the shell.")
        
        print(f"  {Fore.GREEN}exploit{Style.RESET_ALL:<30}- Open exploitation menu (FTP/NFS/SSH/SMB)")
        print(Fore.BLUE + "="*50 + "\n" + Style.RESET_ALL)
        

    def shell(self):
        while True:
            try:
                cmd = input("Ra3Vector >> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Exiting...")
                break

            if not cmd:
                continue
            if cmd == "help":
                self.help()
            elif cmd == "exit":
                print("good bye")
                break
            elif cmd.startswith("scan now"):
                # allow simple inline overrides: scan now targets=1.1.1.1 output=outdir
                parts = cmd.split()
                overrides = {}
                for p in parts[2:]:
                    if '=' in p:
                        k, v = p.split('=', 1)
                        overrides[k.strip()] = v.strip()
                threading.Thread(target=self.run_scan, kwargs={
                    "targets": overrides.get("targets"),
                    "output": overrides.get("output"),
                    "nvd_api_key": overrides.get("nvd_api_key")
                }, daemon=True).start()
            elif cmd.startswith("schedule add"):
                parts = cmd.split()
                if len(parts) != 8:
                    print("[!] Usage: schedule add <id> <min> <hour> <dom> <month> <dow>")
                    continue
                _, _, job_id, minute, hour, day, month, dow = parts
                self.add_schedule(job_id, minute, hour, day, month, dow)
            elif cmd == "schedule list":
                self.list_schedules()
            elif cmd.startswith("schedule remove"):
                parts = cmd.split()
                if len(parts) != 3:
                    print("[!] Usage: schedule remove <id>")
                    continue
                self.remove_schedule(parts[2])
            elif cmd.startswith("set default"):
                parts = cmd.split(maxsplit=3)
                if len(parts) != 4:
                    print("[!] Usage: set default <key> <value>")
                    continue
                _, _, key, value = parts
                self.set_default(key, value)
            elif cmd == "exploit":
                print("[+] Loading exploitation framework menu...")
                exploit_menu()
            else:
                print(f"Unknown command: {cmd}")


# -----------------------------
# ---- main entrypoint ----
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description='Merged Scanner Shell (RaVector + S.A.V.R.)')
    parser.add_argument('--cli', action='store_true', help='Start interactive shell (default)')
    parser.add_argument('--targets', '-t', help='Run a one-off scan (targets) and exit')
    parser.add_argument('--output', '-o', default='reports', help='Output directory for one-off scan')
    parser.add_argument('--nvd-api-key', help='NVD API key for one-off scan')
    args = parser.parse_args()

    if args.targets:
        # one-off CLI scan
        try:
            results = orchestrate_scan(args.targets, args.output, nvd_api_key=args.nvd_api_key)
            print('\nScan complete. Reports generated:')
            print(f"  JSON: {results.get('json')}")
            print(f"  PDF:  {results.get('pdf')}")
        except Exception as e:
            print(f"[!] Scan failed: {e}")
        return

    # default: start interactive shell
    shell = ScanCoreShell()
    shell.shell()

if __name__ == "__main__":
    main()
