#!/usr/bin/env python3
import subprocess
import os
import argparse
import re
from datetime import datetime
import requests
import json
import time
from urllib.request import urlopen, URLError

class CyberSift:
    VERSION = "1.10"

    def __init__(self, target, output_dir="Recon_output", verbose=True):
        self.target = target.strip()
        self.output_dir = output_dir
        self.verbose = verbose
        self.base_name = self.target.replace('.', '_')
        self.results = {
            "target": self.target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tool": "CyberSift",
            "version": self.VERSION,
            "verbose": self.verbose,
            "whois": "",
            "nslookup": "",
            "dig": "",
            "traceroute": "",
            "ports": "",
            "subdomains": [],
            "crtsh_subdomains": [],
            "directories": [],
            "nuclei_results": [],
            "nikto_results": []
        }
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, message, level="INFO"):
        if self.verbose or level in ["ERROR", "WARNING"]:
            prefix = {"INFO": "[*]", "SUCCESS": "[+]", "ERROR": "[!]", "WARNING": "[?]", "DEBUG": "[~]"}.get(level, "[*]")
            print(f"{prefix} CyberSift: {message}")

    def save_txt(self, filename, content, mode="w"):
        """Save content to .txt file and log."""
        path = os.path.join(self.output_dir, filename)
        try:
            with open(path, mode) as f:
                f.write(content + "\n")
            self.log(f"Saved: {path}", level="INFO")
        except Exception as e:
            self.log(f"Failed to save {filename}: {e}", level="ERROR")

    def print_banner(self):
        banner = f"""
   █████████             █████                         █████████   ███     ██████   █████   
  ███░░░░░███           ░░███                         ███░░░░░███ ░░░     ███░░███ ░░███    
 ███     ░░░  █████ ████ ░███████   ██████  ████████ ░███    ░░░  ████   ░███ ░░░  ███████  
░███         ░░███ ░███  ░███░░███ ███░░███░░███░░███░░█████████ ░███  ███████   ░░░███░   
░███          ░███ ░███  ░███ ░███░███████  ░███ ░░░  ░░░░░░░░███ ░███ ░░░███░      ░███    
░░███     ███ ░███ ░███  ░███ ░███░███░░░   ░███      ███    ░███ ░███   ░███       ░███ ███
 ░░█████████  ░░███████  ████████ ░░██████  █████    ░█████████  █████  █████      ░░█████ 
  ░░░░░░░░░    ░░░░░███ ░░░░░░░░   ░░░░░░  ░░░░░      ░░░░░░░░░  ░░░░░  ░░░░░        ░░░░░  
               ███ ░███                                                                     
              ░░██████                                                                      
               ░░░░░░                                                                       
        v{self.VERSION}
        """
        print(banner)

    def run_command(self, cmd, output_file=None, capture=True):
        self.log(f"Executing: {cmd}", level="DEBUG")
        try:
            if capture:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True,)
                if result.stderr and self.verbose:
                    for line in result.stderr.strip().splitlines():
                        if line.strip():
                            self.log(f"stderr: {line}", level="WARNING")
                output = result.stdout.strip()
            else:
                result = subprocess.run(cmd, shell=True,)
                output = ""
            if output_file and capture and output:
                self.save_txt(output_file, output)
            return output
        except subprocess.TimeoutExpired:
            self.log(f"Timeout: {cmd}", level="ERROR")
            return ""
        except Exception as e:
            self.log(f"Error in command: {e}", level="ERROR")
            return ""

    # crt.sh
    def crtsh_enumeration(self):
        self.log(f"Starting crt.sh for {self.target}...", level="INFO")
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        txt_file = f"crtsh_{self.base_name}.txt"
        max_retries = 3
        raw_data = ""
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 503:
                    wait = 2 ** attempt + 1
                    self.log(f"503 from crt.sh. Retrying in {wait}s... ({attempt+1}/{max_retries})", level="WARNING")
                    time.sleep(wait)
                    continue
                response.raise_for_status()
                raw_data = response.text.strip()
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    self.log(f"crt.sh failed after {max_retries} tries: {e}", level="ERROR")
                    self.save_txt(txt_file, f"[!] crt.sh failed: {e}")
                    self.results["crtsh_subdomains"] = []
                    return
                time.sleep(2 ** attempt)
        subdomains = set()
        try:
            certs = json.loads(raw_data) if raw_data else []
            for cert in certs:
                if cert.get("common_name"):
                    cn = cert["common_name"].strip().lower()
                    if cn.endswith('.' + self.target.lower()) or cn == self.target.lower():
                        subdomains.add(cn)
                if cert.get("name_value"):
                    san_text = cert["name_value"]
                    try:
                        sans = json.loads(san_text) if isinstance(san_text, str) else san_text
                    except:
                        sans = [san_text]
                    for san in (sans if isinstance(sans, list) else [sans]):
                        s = san.strip().lower()
                        if s.endswith('.' + self.target.lower()) or s == self.target.lower():
                            subdomains.add(s)
            unique = sorted(subdomains)
            self.results["crtsh_subdomains"] = unique
            txt_content = "\n".join(unique) if unique else "No subdomains found."
            self.save_txt(txt_file, txt_content)
            self.log(f"crt.sh: {len(unique)} subdomains → {txt_file}", level="SUCCESS")
            if self.verbose and unique:
                preview = unique[:10]
                self.log("Sample:\n" + "\n".join(preview) + ("\n..." if len(unique) > 10 else ""), level="INFO")
        except Exception as e:
            self.save_txt(txt_file, f"[!] Parse error: {e}")
            self.results["crtsh_subdomains"] = []

    # Whois Lookup
    def whois_lookup(self):
        file = f"whois_{self.base_name}.txt"
        output = self.run_command(f"whois {self.target}", file)
        self.results["whois"] = output
        self.log("WHOIS saved." if output else "WHOIS failed.", level="INFO" if output else "WARNING")

    # Nslookup
    def nslookup_lookup(self):
        file = f"nslookup_{self.base_name}.txt"
        output = self.run_command(f"nslookup -query=any {self.target}", file)
        self.results["nslookup"] = output
        self.log("NSLOOKUP saved." if output else "NSLOOKUP failed.", level="INFO" if output else "WARNING")

    # Dig
    def dig_lookup(self):
        file = f"dig_{self.base_name}.txt"
        output = self.run_command(f"dig {self.target} ANY +nocomments +noquestion +noauthority +noadditional", file)
        self.results["dig"] = output
        self.log("DIG saved." if output else "DIG failed.", level="INFO" if output else "WARNING")

    # Traceroute
    def traceroute_scan(self):
        file = f"traceroute_{self.base_name}.txt"
        output = self.run_command(f"traceroute -w 3 -q 3 {self.target}", file)
        self.results["traceroute"] = output
        self.log("Traceroute saved." if output else "Traceroute failed.", level="INFO" if output else "WARNING")

    # Nmap
    def port_scanning(self):
        file = f"nmap_{self.base_name}.txt"
        path = os.path.join(self.output_dir, file)
        self.run_command(f"nmap -sS {self.target} -p- -oN {path}", capture=False)
        if os.path.exists(path):
            with open(path) as f:
                output = f.read().strip()
            self.results["ports"] = output
            open_ports = [l for l in output.splitlines() if "open" in l]
            self.log(f"Nmap: {len(open_ports)} open ports → {file}", level="SUCCESS")
        else:
            self.log("Nmap failed.", level="WARNING")

    def subdomain_enumeration(self):
        self.log("Running subdomain tools...", level="INFO")
        subdomains = list(self.results["crtsh_subdomains"])
        # Subfinder
        file = f"subfinder_{self.base_name}.txt"
        path = os.path.join(self.output_dir, file)
        self.run_command(f"subfinder -d {self.target} -o {path} -silent", capture=False)
        if os.path.exists(path):
            with open(path) as f:
                subs = [l.strip() for l in f if l.strip()]
            subdomains.extend(subs)
            self.log(f"Subfinder → {file}", level="SUCCESS")
        # Amass
        file = f"amass_{self.base_name}.txt"
        path = os.path.join(self.output_dir, file)
        self.run_command(f"amass enum -active -d {self.target} -o {path}", capture=False)
        if os.path.exists(path):
            with open(path) as f:
                subs = [l.strip() for l in f if l.strip()]
            subdomains.extend(subs)
            self.log(f"Amass → {file}", level="SUCCESS")
        # Sublist3r
        file = f"sublist3r_{self.base_name}.txt"
        output = self.run_command(f"sublist3r -d {self.target} -o {os.path.join(self.output_dir, file)} -v", file)
        if output:
            subs = [l.strip() for l in output.splitlines() if '.' in l and not l.startswith('[-]')]
            subdomains.extend(subs)
            self.log(f"Sublist3r → {file}", level="SUCCESS")
        # theHarvester
        file = f"theharvester_{self.base_name}.txt"
        path = os.path.join(self.output_dir, file)
        self.run_command(f"theHarvester -d {self.target} -b all -f {path}", capture=False)
        if os.path.exists(path):
            with open(path) as f:
                content = f.read()
            subs = [l.strip() for l in content.splitlines() if self.target in l and '.' in l and not l.startswith(('-', '*', '['))]
            subdomains.extend(subs)
            self.log(f"theHarvester → {file}", level="SUCCESS")
        # fierce
        file = f"fierce_{self.base_name}.txt"
        path = os.path.join(self.output_dir, file)
        self.run_command(f"fierce --domain {self.target} > {path}", capture=False)
        if os.path.exists(path):
            with open(path) as f:
                subs = [l.strip() for l in f if l.strip() and re.search(r'\b([a-zA-Z0-9.-]+\.' + re.escape(self.target) + r')\b', l)]
            subdomains.extend(subs)
            self.log(f"fierce → {file}", level="SUCCESS")
        subdomains = sorted(list(set(subdomains)))
        self.results["subdomains"] = subdomains
        self.log(f"Total unique subdomains: {len(subdomains)}", level="SUCCESS")

    def directory_enumeration(self):
        file = f"dirb_{self.base_name}.txt"
        wordlist = "/usr/share/dirb/wordlists/common.txt"
        if not os.path.isfile(wordlist):
            self.log("Dirb wordlist missing!", level="ERROR")
        else:
            # dirb
            path = os.path.join(self.output_dir, file)
            self.run_command(f"dirb http://{self.target} {wordlist} -f -o {path}", capture=False)
            if os.path.exists(path):
                with open(path) as f:
                    dirs = [l[2:].split(" ")[0] for l in f if l.strip().startswith("+ ")]
                self.results["directories"] = dirs
                self.log(f"Dirb: {len(dirs)} dirs → {file}", level="SUCCESS")

        # dirsearch
        file_dirsearch = f"dirsearch_{self.base_name}.txt"
        path_dirsearch = os.path.join(self.output_dir, file_dirsearch)
        wordlist_dirsearch = "/usr/share/wordlists/dirsearch/db/common.txt"
        if os.path.isfile(wordlist_dirsearch):
            self.run_command(f"dirsearch -u http://{self.target} -w {wordlist_dirsearch} -e php,html,js,txt,bak,zip -f --plain-text-report={path_dirsearch}", capture=False)
            if os.path.exists(path_dirsearch):
                with open(path_dirsearch) as f:
                    dirs_ds = []
                    for line in f:
                        if " -> " in line and "[Status:" in line:
                            url_part = line.split(" -> ")[0].strip()
                            if url_part.startswith("http"):
                                dirs_ds.append(url_part.split(self.target, 1)[-1].lstrip('/'))
                            else:
                                dirs_ds.append(url_part)
                    self.results["directories"].extend(dirs_ds)
                    self.log(f"Dirsearch: {len(dirs_ds)} dirs → {file_dirsearch}", level="SUCCESS")
        else:
            self.log("Dirsearch wordlist not found (common.txt)", level="WARNING")

    # Nuclei
    def nuclei_scan(self):
        file = f"nuclei_{self.base_name}.txt"
        path = os.path.join(self.output_dir, file)
        self.run_command(f"nuclei -u http://{self.target} -o {path} -silent", capture=False)
        if os.path.exists(path):
            with open(path) as f:
                vulns = [l.strip() for l in f if l.strip()]
            self.results["nuclei_results"] = vulns
            self.log(f"Nuclei: {len(vulns)} findings → {file}", level="SUCCESS")

    # Nikto
    def nikto_scan(self):
        file = f"nikto_{self.base_name}.txt"
        path = os.path.join(self.output_dir, file)
        self.run_command(f"nikto -h http://{self.target} -output {path}", capture=False)
        if os.path.exists(path):
            with open(path) as f:
                issues = [l.strip() for l in f if l.strip().startswith("+ ")]
            self.results["nikto_results"] = issues
            self.log(f"Nikto: {len(issues)} issues → {file}", level="SUCCESS")

    def save_report(self):
        report = os.path.join(self.output_dir, f"cybersift_report_{self.base_name}.txt")
        try:
            with open(report, "w") as f:
                f.write(f"CyberSift v{self.VERSION} Report\n")
                f.write(f"Target: {self.target} | {self.results['timestamp']}\n")
                f.write("="*60 + "\n\n")
                f.write("OUTPUT FILES:\n")
                txt_files = [f for f in os.listdir(self.output_dir) if f.endswith(".txt")]
                for file in sorted(txt_files):
                    f.write(f" • {file}\n")
                f.write("\n" + "="*60 + "\n\n")
                f.write(f"SUMMARY:\n")
                f.write(f" • crt.sh subdomains: {len(self.results['crtsh_subdomains'])}\n")
                f.write(f" • Total subdomains: {len(self.results['subdomains'])}\n")
                f.write(f" • Open ports: {len([l for l in self.results['ports'].splitlines() if 'open' in l])}\n")
                f.write(f" • Directories: {len(self.results['directories'])}\n")
                f.write(f" • Nuclei findings: {len(self.results['nuclei_results'])}\n")
                f.write(f" • Nikto issues: {len(self.results['nikto_results'])}\n")
            self.log(f"Final report → {report}", level="SUCCESS")
        except Exception as e:
            self.log(f"Report save failed: {e}", level="ERROR")

    def run(self):
        self.print_banner()
        start = datetime.now()
        self.log(f"Starting scan on {self.target}...", level="INFO")
        self.crtsh_enumeration()
        self.whois_lookup()
        self.nslookup_lookup()
        self.dig_lookup()
        self.traceroute_scan()
        self.port_scanning()
        self.subdomain_enumeration()
        self.directory_enumeration()
        self.nuclei_scan()
        self.nikto_scan()
        self.save_report()
        self.log(f"Done in {(datetime.now() - start).total_seconds():.1f}s", level="SUCCESS")

def main():
    parser = argparse.ArgumentParser(description="CyberSift - Full Recon with .txt Output")
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default="Recon_output", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', args.target):
        print("[!] Invalid domain.")
        return
    recon = CyberSift(args.target, args.output, args.verbose)
    recon.run()

if __name__ == "__main__":
    main()
