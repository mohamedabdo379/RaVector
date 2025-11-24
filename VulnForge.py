"""
Merged vulnerability scanner script
- Combines scanner_core.py, cve_integration.py, report_generator.py
- NVD v2.0 integration with provided API key
- Usage: python3 Scanner.py --targets 192.168.65.128 --output reports
"""

import os
import json
import argparse
import time
from datetime import datetime
from time import sleep

# Optional imports with friendly error messages
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


class BasicVulnerabilityScanner:
    def __init__(self):
        if nmap is None:
            raise RuntimeError("python-nmap is required. Install with: pip install python-nmap and ensure nmap is installed on your system.")
        self.nm = nmap.PortScanner()

    def host_discovery(self, target_range):
        """Discover active hosts in the given target range using -sn (ping sweep)."""
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
                    # sometimes nmap host state access may fail
                    continue
            return active_hosts
        except Exception as e:
            print(f"[-] Host discovery failed: {e}")
            return []

    def service_enumeration(self, target_host):
        """Run a service/version scan against a host and collect structured info."""
        print(f"[+] Scanning services on: {target_host}")
        try:
            # Auto-switch: use -sS if root, otherwise fallback to -sT
            try:
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    scan_args = '-sV -sS -T4 --version-intensity 5'
                else:
                    scan_args = '-sV -sT -T4 --version-intensity 5'
            except Exception:
                # On platforms without geteuid (e.g. Windows), just use -sV -T4
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
        """Run a set of NSE scripts against a host and return any script-detected issues."""
        print(f"[+] Running NSE scripts on: {target_host}")
        if nse_scripts is None:
            nse_scripts = ['vuln', 'http-vuln-*', 'ssh-auth-methods', 'smb-vuln-*']

        try:
            nse_args = f'-sV --script {",".join(nse_scripts)}'
            self.nm.scan(hosts=target_host, arguments=nse_args)

            vulnerabilities = []
            if target_host in self.nm.all_hosts() and 'script' in self.nm[target_host]:
                for script_name, script_output in self.nm[target_host]['script'].items():
                    out_str = str(script_output)
                    # simple heuristic: look for keywords
                    if any(k in out_str.upper() for k in ['VULNERABLE', 'ERROR', 'WARNING']):
                        vulnerabilities.append({
                            'script': script_name,
                            'output': script_output,
                            'risk': 'Medium'
                        })
                        print(f"    [!] Vulnerability found by script: {script_name}")

            return vulnerabilities
        except Exception as e:
            print(f"[-] NSE scanning failed: {e}")
            return []


class CVEIntegration:
    def __init__(self, api_key=None, user_agent="MergedScanner/1.0 (contact: you@example.com)"):
        """
        NVD v2.0 integration.
        The API key is inserted below by default but can be overridden by:
         - constructor parameter api_key
         - environment variable NVD_API_KEY
         - CLI flag --nvd-api-key (wired in main)
        """
        if requests is None:
            raise RuntimeError("requests is required. Install with: pip install requests")

        # NVD v2.0 endpoint
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # ---- INSERTED API KEY (from user) ----
        # Default hard-coded value (you asked to insert it). Can be overridden.
        default_key = "43b82294-7a9d-4487-af55-983fcda7fbf6"
        # --------------------------------------

        # Resolution order: constructor arg -> env var -> hard-coded default
        self.api_key = api_key or os.environ.get("NVD_API_KEY") or default_key
        self.user_agent = user_agent
        if not self.api_key:
            print("[!] Warning: NVD API key is not set. NVD requests may fail with 403 Forbidden.")

        self.cve_cache = {}

    def extract_software_info(self, service_info):
        software_mapping = {
            'apache': 'apache http server',
            'nginx': 'nginx',
            'microsoft-iis': 'internet information services',
            'openssh': 'openssh',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'vsftpd': 'vsftpd',
            'proftpd': 'proftpd'
        }

        product = (service_info.get('product') or '').lower()
        version = service_info.get('version') or ''
        for key, value in software_mapping.items():
            if key in product:
                return value, version
        return service_info.get('service', '').lower(), version

    def _do_request_with_retries(self, params, max_retries=3, backoff_factor=1.0):
        """
        Do GET with simple exponential backoff for 429/5xx.
        Returns response or None.
        """
        headers = {
            "User-Agent": self.user_agent
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        attempt = 0
        while attempt <= max_retries:
            try:
                resp = requests.get(self.nvd_api_url, params=params, headers=headers, timeout=15)
            except Exception as e:
                # Network-level exception; retry
                attempt += 1
                sleep(backoff_factor * attempt)
                continue

            if resp.status_code == 200:
                return resp
            # rate limited or server error -> retry
            if resp.status_code in (429, 502, 503, 504):
                attempt += 1
                sleep(backoff_factor * (2 ** (attempt - 1)))
                continue

            # other non-retryable codes (403, 400, etc.)
            return resp

        return None

    def search_cve_online(self, software_name, version):
        """
        Query NVD v2.0 with keywordSearch and return normalized list of vulnerabilities.
        """
        if not software_name:
            return []

        cache_key = f"{software_name}_{version}"
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]

        if not self.api_key:
            print("[-] Skipping NVD lookup: no API key configured.")
            return []

        query = f"{software_name} {version}".strip() if version else software_name
        params = {
            "keywordSearch": query,
            "resultsPerPage": 20
        }

        resp = self._do_request_with_retries(params)
        if resp is None:
            print("[-] NVD request failed after retries.")
            return []
        if resp.status_code != 200:
            print(f"[-] NVD API request failed: {resp.status_code}")
            try:
                print(resp.text[:400])
            except Exception:
                pass
            return []

        try:
            data = resp.json()
        except Exception as e:
            print(f"[-] Failed to parse NVD JSON: {e}")
            return []

        # v2.0 returns "vulnerabilities": [ { "cve": {...} }, ... ]
        items = data.get("vulnerabilities", [])
        vulnerabilities = []
        for item in items:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")

            # description: prefer english if present
            descriptions = cve_obj.get("descriptions", []) or []
            description = ""
            if descriptions:
                for d in descriptions:
                    if d.get("lang") and d.get("lang").lower().startswith("en"):
                        description = d.get("value", "")
                        break
                if not description:
                    description = descriptions[0].get("value", "")

            # metrics: try v3.1 -> v3.0 -> v2
            metrics = cve_obj.get("metrics", {}) or {}
            base_score = "Unknown"
            try:
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    base_score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "Unknown")
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    base_score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", "Unknown")
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    base_score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", "Unknown")
            except Exception:
                base_score = "Unknown"

            vulnerabilities.append({
                "cve_id": cve_id,
                "description": (description[:200] + "...") if len(description) > 200 else description,
                "cvss_score": base_score,
                "software": software_name,
                "version": version
            })

        # cache and return
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
                            cve.update({
                                'port': port,
                                'protocol': proto,
                                'service': service_info.get('service')
                            })
                            all_vulnerabilities.append(cve)
                        # polite delay (NVD has low rate limits)
                        sleep(1)
        return all_vulnerabilities


class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_json_report(self, scan_data, filename=None):
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'vulnerability_scan_{timestamp}.json'
        filepath = os.path.join(self.output_dir, filename)
        report = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'scanner_version': 'MergedScanner 1.0',
                'targets_scanned': len(scan_data.get('hosts', []))
            },
            'executive_summary': self._generate_executive_summary(scan_data),
            'detailed_findings': scan_data.get('hosts', []),
            'risk_statistics': self._calculate_risk_stats(scan_data)
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON report generated: {filepath}")
        return filepath

    def generate_excel_report(self, scan_data, filename=None):
        if pd is None:
            print("[!] pandas is required to generate Excel report. Install with: pip install pandas openpyxl")
            return None
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'vulnerability_scan_{timestamp}.xlsx'
        filepath = os.path.join(self.output_dir, filename)

        excel_data = []
        for host_data in scan_data.get('hosts', []):
            hostname = host_data.get('hostname', '')
            for proto, ports in host_data.get('protocols', {}).items():
                for port, service_info in ports.items():
                    excel_data.append({
                        'Host': hostname,
                        'Protocol': proto,
                        'Port': port,
                        'Service': service_info.get('service', ''),
                        'Version': service_info.get('version', ''),
                        'State': service_info.get('state', ''),
                        'Risk Level': 'Info'
                    })
            for vuln in host_data.get('vulnerabilities', []):
                excel_data.append({
                    'Host': hostname,
                    'Protocol': vuln.get('protocol', 'N/A'),
                    'Port': vuln.get('port', 'N/A'),
                    'Service': vuln.get('service', 'N/A'),
                    'CVE ID': vuln.get('cve_id', 'N/A'),
                    'CVSS Score': vuln.get('cvss_score', 'Unknown'),
                    'Description': vuln.get('description', ''),
                    'Risk Level': self._determine_risk_level(vuln.get('cvss_score'))
                })

        df = pd.DataFrame(excel_data)
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
            summary_data = self._create_summary_sheet(scan_data)
            summary_df = pd.DataFrame([summary_data])
            summary_df.to_excel(writer, sheet_name='Executive_Summary', index=False)

        print(f"[+] Excel report generated: {filepath}")
        return filepath

    def _determine_risk_level(self, cvss_score):
        try:
            score = float(cvss_score)
            if score >= 9.0:
                return 'Critical'
            elif score >= 7.0:
                return 'High'
            elif score >= 4.0:
                return 'Medium'
            elif score > 0:
                return 'Low'
            else:
                return 'Info'
        except Exception:
            return 'Info'

    def _generate_executive_summary(self, scan_data):
        total_hosts = len(scan_data.get('hosts', []))
        total_vulnerabilities = 0
        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for host in scan_data.get('hosts', []):
            total_vulnerabilities += len(host.get('vulnerabilities', []))
            for vuln in host.get('vulnerabilities', []):
                lvl = self._determine_risk_level(vuln.get('cvss_score'))
                risk_counts[lvl] = risk_counts.get(lvl, 0) + 1
        return {
            'total_hosts_scanned': total_hosts,
            'total_vulnerabilities_found': total_vulnerabilities,
            'risk_distribution': risk_counts,
            'scan_duration': scan_data.get('scan_duration', 'Unknown'),
            'recommendations': self._generate_recommendations(risk_counts)
        }

    def _calculate_risk_stats(self, scan_data):
        return {"total_risks": sum(len(h.get('vulnerabilities', [])) for h in scan_data.get('hosts', []))}

    def _create_summary_sheet(self, scan_data):
        return {"scan_summary": f"Scanned {len(scan_data.get('hosts', []))} hosts"}

    def _generate_recommendations(self, risk_counts):
        recommendations = []
        if risk_counts.get('Critical', 0) + risk_counts.get('High', 0) > 0:
            recommendations.append("Immediate patching required for critical and high-risk vulnerabilities")
        if risk_counts.get('Medium', 0) > 5:
            recommendations.append("Schedule maintenance window for medium-risk remediation")
        recommendations.append("Implement continuous vulnerability monitoring")
        recommendations.append("Review and harden network security configurations")
        return recommendations


def orchestrate_scan(targets, output_dir, nvd_api_key=None):
    start_time = time.time()
    # CVEIntegration will use constructor arg, env var, or the hard-coded default key
    cve_checker = CVEIntegration(api_key=nvd_api_key)
    scanner = BasicVulnerabilityScanner()
    reporter = ReportGenerator(output_dir=output_dir)

    scan_data = {'hosts': [], 'scan_start': datetime.now().isoformat()}

    targets_list = [t.strip() for t in targets.split(',') if t.strip()]

    # If user provided a CIDR or range, first do discovery on the first entry
    discovery_targets = targets_list
    for target_range in discovery_targets:
        active = scanner.host_discovery(target_range)
        # if discovery returned hosts, replace targets_list with discovered hosts
        if active:
            targets_to_scan = active
        else:
            targets_to_scan = [target_range]

        for host in targets_to_scan:
            svc = scanner.service_enumeration(host)
            if svc is None:
                continue
            # run NSE scripts (optional heavy)
            nse_vulns = scanner.run_nse_scripts(host)
            # integrate CVE info
            cve_vulns = cve_checker.analyze_service_vulnerabilities(svc)
            # attach vulnerabilities
            svc['vulnerabilities'] = nse_vulns + cve_vulns
            scan_data['hosts'].append(svc)

    scan_data['scan_end'] = datetime.now().isoformat()
    scan_data['scan_duration'] = f"{time.time() - start_time:.1f}s"

    # generate reports
    json_path = reporter.generate_json_report(scan_data)
    excel_path = reporter.generate_excel_report(scan_data)

    return {'json': json_path, 'excel': excel_path}


def main():
    parser = argparse.ArgumentParser(description='Merged Vulnerability Scanner')
    parser.add_argument('--targets', '-t', required=True, help='Targets to scan (CIDR, range, or comma-separated hosts)')
    parser.add_argument('--output', '-o', default='reports', help='Output directory for reports')
    parser.add_argument('--nvd-api-key', help='NVD API key (overrides env var or hard-coded default)')
    args = parser.parse_args()

    try:
        results = orchestrate_scan(args.targets, args.output, nvd_api_key=args.nvd_api_key)
        print('\nScan complete. Reports:')
        print(f"  JSON: {results.get('json')}")
        print(f"  Excel: {results.get('excel')}")
    except Exception as e:
        print(f"[!] Scan failed: {e}")


if __name__ == '__main__':
    main()
