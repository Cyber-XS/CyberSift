#!/usr/bin/env python3

import subprocess
import os
import argparse
from datetime import datetime

class CyberSift:
    VERSION = "1.5"

    def __init__(self, target, output_dir="Recon_output", verbose=True):
        self.target = target.strip()
        self.output_dir = output_dir
        self.verbose = verbose
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            "target": self.target,
            "timestamp": self.timestamp,
            "tool": "CyberSift",
            "version": self.VERSION,
            "verbose": self.verbose,
            "whois": "",
            "nslookup": "",
            "ports": "",
            "subdomains": [],
            "directories": [],
            "nuclei_results": [],
            "nikto_results": []
        }
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, message, level="INFO"):
        """Print message if verbose is enabled or if level is ERROR."""
        if self.verbose or level in ["ERROR", "WARNING"]:
            prefix = {
                "INFO": "[*]",
                "SUCCESS": "[+]",
                "ERROR": "[!]",
                "WARNING": "[?]",
                "DEBUG": "[~]"
            }.get(level, "[*]")
            print(f"{prefix} CyberSift: {message}")

    def print_banner(self):
        """Display CyberSift banner."""
        banner = """
   █████████             █████                         █████████   ███     ██████   █████   
  ███░░░░░███           ░░███                         ███░░░░░███ ░░░     ███░░███ ░░███    
 ███     ░░░  █████ ████ ░███████   ██████  ████████ ░███    ░░░  ████   ░███ ░░░  ███████  
░███         ░░███ ░███  ░███░░███ ███░░███░░███░░███░░█████████ ░███  ███████   ░░░███░   
░███          ░███ ░███  ░███ ░███░███████  ░███ ░░░  ░░░░░░░░███ ░███ ░░░███░      ░███    
░░███     ███ ░███ ░███  ░███ ░███░███░░░   ░███      ███    ░███ ░███   ░███       ░███ ███
 ░░█████████  ░░███████  ████████ ░░██████  █████    ░░█████████  █████  █████      ░░█████ 
  ░░░░░░░░░    ░░░░░███ ░░░░░░░░   ░░░░░░  ░░░░░      ░░░░░░░░░  ░░░░░  ░░░░░        ░░░░░  
               ███ ░███                                                                     
              ░░██████                                                                      
               ░░░░░░                                                                       
        v{}
        """.format(self.VERSION)
        print(banner)

    def run_command(self, cmd, output_file=None, capture=True):
        """Execute a shell command and optionally save output."""
        self.log(f"Executing command: {cmd}", level="DEBUG")
        try:
            if capture:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                if result.stderr and self.verbose:
                    for line in result.stderr.strip().splitlines():
                        if line.strip():
                            self.log(f"stderr: {line}", level="WARNING")
                output = result.stdout.strip()
            else:
                result = subprocess.run(cmd, shell=True, timeout=600)
                output = ""

            if output_file:
                file_path = os.path.join(self.output_dir, output_file)
                if capture and output:
                    with open(file_path, "w") as f:
                        f.write(output + "\n")
                    self.log(f"Output saved to {file_path}", level="INFO")
                # If not capturing, tool wrote directly

            return output
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after 600s: {cmd}"
            self.log(error_msg, level="ERROR")
            return None
        except Exception as e:
            error_msg = f"Exception in command '{cmd}': {str(e)}"
            self.log(error_msg, level="ERROR")
            return None

    def whois_lookup(self):
        """Run WHOIS lookup on the target domain."""
        self.log(f"Starting WHOIS lookup for {self.target}...", level="INFO")
        whois_file = "whois.txt"
        whois_cmd = f"whois {self.target}"

        output = self.run_command(whois_cmd, whois_file)
        self.results["whois"] = output if output else ""

        if output:
            self.log("WHOIS lookup completed.", level="SUCCESS")
            if self.verbose:
                preview = "\n".join(output.splitlines()[:15])
                self.log(f"WHOIS preview:\n{preview}" + ("\n..." if len(output.splitlines()) > 15 else ""), level="INFO")
        else:
            self.log("WHOIS lookup failed or no data returned.", level="WARNING")

    def nslookup_lookup(self):
        """Run NSLOOKUP to get DNS records (A, MX, NS, TXT)."""
        self.log(f"Starting NSLOOKUP for {self.target}...", level="INFO")
        nslookup_file = "nslookup.txt"
        nslookup_cmd = f"nslookup {self.target}"

        output = self.run_command(nslookup_cmd, nslookup_file)
        self.results["nslookup"] = output if output else ""

        if output:
            self.log("NSLOOKUP completed.", level="SUCCESS")
            if self.verbose:
                preview = "\n".join(output.splitlines()[:12])
                self.log(f"NSLOOKUP preview:\n{preview}" + ("\n..." if len(output.splitlines()) > 12 else ""), level="INFO")
        else:
            self.log("NSLOOKUP failed or no data returned.", level="WARNING")

    def port_scanning(self):
        """Run Nmap for basic port scanning on the target domain."""
        self.log(f"Starting port scanning for {self.target}...", level="INFO")

        nmap_file = "nmap.txt"
        nmap_file_path = os.path.join(self.output_dir, nmap_file)
        nmap_cmd = f"nmap -sS {self.target} -oN {nmap_file_path}"

        self.run_command(nmap_cmd, capture=False)
        if os.path.exists(nmap_file_path):
            with open(nmap_file_path, "r") as f:
                output = f.read().strip()
        else:
            output = ""

        self.results["ports"] = output

        if output:
            open_ports = [line for line in output.splitlines() if "/tcp" in line and "open" in line]
            self.log(f"Port scanning completed. Found {len(open_ports)} open ports.", level="SUCCESS")
            if self.verbose and open_ports:
                self.log("Open ports:\n" + "\n".join(open_ports[:10]) + ("\n..." if len(open_ports) > 10 else ""), level="INFO")
        else:
            self.log("Port scanning failed or returned no output.", level="WARNING")

    def subdomain_enumeration(self):
        """Run Subfinder, Amass, and Sublist3r for subdomain enumeration."""
        self.log(f"Starting subdomain enumeration for {self.target}...", level="INFO")
        subdomains = []

        subfinder_file = "subfinder.txt"
        subfinder_file_path = os.path.join(self.output_dir, subfinder_file)
        subfinder_cmd = f"subfinder -d {self.target} -o {subfinder_file_path} -silent"
        
        self.run_command(subfinder_cmd, capture=False)
        if os.path.exists(subfinder_file_path):
            with open(subfinder_file_path, "r") as f:
                subfinder_output = f.read().strip()
            subfinder_subdomains = [line.strip() for line in subfinder_output.splitlines() if line.strip() and not line.startswith("[")]
            subdomains.extend(subfinder_subdomains)
            self.log(f"Found {len(subfinder_subdomains)} subdomains with Subfinder.", level="SUCCESS")
            if self.verbose and subfinder_subdomains:
                preview = subfinder_subdomains[:10]
                self.log("Sample Subfinder subdomains:\n" + "\n".join(preview) + ("\n..." if len(subfinder_subdomains) > 10 else ""), level="INFO")
        else:
            self.log("Subfinder enumeration failed or no results.", level="WARNING")

        amass_file = "amass.txt"
        amass_file_path = os.path.join(self.output_dir, amass_file)
        amass_cmd = f"amass enum -active -d {self.target} -o {amass_file_path} -silent"
        
        self.run_command(amass_cmd, capture=False)
        if os.path.exists(amass_file_path):
            with open(amass_file_path, "r") as f:
                amass_output = f.read().strip()
            amass_subdomains = [line.strip() for line in amass_output.splitlines() if line.strip() and not line.startswith("[")]
            subdomains.extend(amass_subdomains)
            self.log(f"Found {len(amass_subdomains)} subdomains with Amass.", level="SUCCESS")
            if self.verbose and amass_subdomains:
                preview = amass_subdomains[:10]
                self.log("Sample Amass subdomains:\n" + "\n".join(preview) + ("\n..." if len(amass_subdomains) > 10 else ""), level="INFO")
        else:
            self.log("Amass enumeration failed or no results.", level="WARNING")

        sublist3r_file = "sublist3r.txt"
        sublist3r_cmd = f"sublist3r -d {self.target} -o {os.path.join(self.output_dir, sublist3r_file)} -v"
        
        sublist3r_output = self.run_command(sublist3r_cmd, sublist3r_file)
        if sublist3r_output:
            sublist3r_subdomains = [line.strip() for line in sublist3r_output.splitlines() if line.strip() and '.' in line and not line.startswith('[-]')]
            subdomains.extend(sublist3r_subdomains)
            self.log(f"Found {len(sublist3r_subdomains)} subdomains with Sublist3r.", level="SUCCESS")
            if self.verbose and sublist3r_subdomains:
                preview = sublist3r_subdomains[:10]
                self.log("Sample Sublist3r subdomains:\n" + "\n".join(preview) + ("\n..." if len(sublist3r_subdomains) > 10 else ""), level="INFO")
        else:
            self.log("Sublist3r enumeration failed or no results.", level="WARNING")

        subdomains = list(set(subdomains))
        self.results["subdomains"] = subdomains
        self.log(f"Total unique subdomains found: {len(subdomains)}.", level="SUCCESS")
        if self.verbose and subdomains:
            preview = subdomains[:10]
            self.log("Sample combined subdomains:\n" + "\n".join(preview) + ("\n..." if len(subdomains) > 10 else ""), level="INFO")

    def directory_enumeration(self):
        """Run Dirb for directory enumeration with specified wordlist."""
        self.log(f"Starting directory enumeration for {self.target}...", level="INFO")

        dirb_file = "dirb.txt"
        wordlist_path = "/usr/share/dirb/wordlists/common.txt"
        
        if not os.path.isfile(wordlist_path):
            self.log(f"Wordlist file not found: {wordlist_path}", level="ERROR")
            return

        dirb_file_path = os.path.join(self.output_dir, dirb_file)
        dirb_cmd = f"dirb http://{self.target} {wordlist_path} -o {dirb_file_path} -S"
        
        self.run_command(dirb_cmd, capture=False)
        directories = []

        if os.path.exists(dirb_file_path):
            with open(dirb_file_path, "r") as f:
                dirb_output = f.read()
            directories = [line.strip() for line in dirb_output.splitlines() if line.strip() and line.startswith("+ ")]
            directories = [line[2:].split(" ")[0] for line in directories]
            self.results["directories"] = directories
            self.log(f"Found {len(directories)} directories.", level="SUCCESS")
            if self.verbose and directories:
                preview = directories[:10]
                self.log("Sample directories:\n" + "\n".join(preview) + ("\n..." if len(directories) > 10 else ""), level="INFO")
        else:
            self.log("Directory enumeration failed or no results.", level="WARNING")
            self.results["directories"] = []

    def nuclei_scan(self):
        """Run Nuclei for vulnerability scanning."""
        self.log(f"Starting Nuclei vulnerability scan for {self.target}...", level="INFO")

        nuclei_file = "nuclei.txt"
        nuclei_file_path = os.path.join(self.output_dir, nuclei_file)
        nuclei_cmd = f"nuclei -u http://{self.target} -o {nuclei_file_path} -silent"
        
        self.run_command(nuclei_cmd, capture=False)
        nuclei_results = []

        if os.path.exists(nuclei_file_path):
            with open(nuclei_file_path, "r") as f:
                nuclei_output = f.read()
            nuclei_results = [line.strip() for line in nuclei_output.splitlines() if line.strip()]
            self.results["nuclei_results"] = nuclei_results
            self.log(f"Found {len(nuclei_results)} vulnerabilities with Nuclei.", level="SUCCESS")
            if self.verbose and nuclei_results:
                preview = nuclei_results[:10]
                self.log("Sample Nuclei findings:\n" + "\n".join(preview) + ("\n..." if len(nuclei_results) > 10 else ""), level="INFO")
        else:
            self.log("Nuclei scan failed or no vulnerabilities found.", level="WARNING")
            self.results["nuclei_results"] = []

    def nikto_scan(self):
        """Run Nikto for web server vulnerability scanning."""
        self.log(f"Starting Nikto vulnerability scan for {self.target}...", level="INFO")

        nikto_file = "nikto.txt"
        nikto_file_path = os.path.join(self.output_dir, nikto_file)
        nikto_cmd = f"nikto -h http://{self.target} -output {nikto_file_path}"
        
        self.run_command(nikto_cmd, capture=False)
        nikto_results = []

        if os.path.exists(nikto_file_path):
            with open(nikto_file_path, "r") as f:
                nikto_output = f.read()
            nikto_results = [line.strip() for line in nikto_output.splitlines() if line.strip() and line.startswith("+ ")]
            self.results["nikto_results"] = nikto_results
            self.log(f"Found {len(nikto_results)} issues with Nikto.", level="SUCCESS")
            if self.verbose and nikto_results:
                preview = nikto_results[:10]
                self.log("Sample Nikto findings:\n" + "\n".join(preview) + ("\n..." if len(nikto_results) > 10 else ""), level="INFO")
        else:
            self.log("Nikto scan failed or no issues found.", level="WARNING")
            self.results["nikto_results"] = []

    def save_report(self):
        """Save results to a TXT report."""
        report_file = os.path.join(self.output_dir, f"cybersift_report_{self.timestamp}.txt")
        try:
            with open(report_file, "w") as f:
                f.write(f"CyberSift Report\n")
                f.write(f"{'='*50}\n")
                f.write(f"Tool: {self.results['tool']} v{self.results['version']}\n")
                f.write(f"Target: {self.results['target']}\n")
                f.write(f"Timestamp: {self.results['timestamp']}\n")
                f.write(f"Verbose Mode: {self.results['verbose']}\n\n")

                # WHOIS
                f.write(f"WHOIS Lookup:\n")
                f.write(f"{'-'*30}\n")
                if self.results["whois"]:
                    f.write(self.results["whois"][:2000] + ("\n..." if len(self.results["whois"]) > 2000 else "") + "\n\n")
                else:
                    f.write("No WHOIS data available.\n\n")

                # NSLOOKUP
                f.write(f"NSLOOKUP Results:\n")
                f.write(f"{'-'*30}\n")
                if self.results["nslookup"]:
                    f.write("\n".join(self.results["nslookup"].splitlines()[:30]) + ("\n..." if len(self.results["nslookup"].splitlines()) > 30 else "") + "\n\n")
                else:
                    f.write("No NSLOOKUP data available.\n\n")

                # Port Scanning
                f.write(f"Port Scanning Results:\n")
                f.write(f"{'-'*30}\n")
                if self.results["ports"]:
                    open_ports = [line for line in self.results["ports"].splitlines() if "/tcp" in line and "open" in line]
                    if open_ports:
                        f.write(f"Open Ports ({len(open_ports)}):\n")
                        f.write("\n".join(open_ports) + "\n\n")
                    else:
                        f.write("No open ports found.\n\n")
                else:
                    f.write("Port scanning failed or returned no output.\n\n")

                # Subdomains
                f.write(f"Subdomain Enumeration Results (Subfinder, Amass, Sublist3r):\n")
                f.write(f"{'-'*30}\n")
                if self.results["subdomains"]:
                    f.write(f"Subdomains Found ({len(self.results['subdomains'])}):\n")
                    f.write("\n".join(self.results['subdomains']) + "\n\n")
                else:
                    f.write("No subdomains found or enumeration failed.\n\n")

                # Directories
                f.write(f"Directory Enumeration Results (Dirb):\n")
                f.write(f"{'-'*30}\n")
                if self.results["directories"]:
                    f.write(f"Directories Found ({len(self.results['directories'])}):\n")
                    f.write("\n".join(self.results['directories']) + "\n\n")
                else:
                    f.write("No directories found or enumeration failed.\n\n")

                # Nuclei
                f.write(f"Vulnerability Scan Results (Nuclei):\n")
                f.write(f"{'-'*30}\n")
                if self.results["nuclei_results"]:
                    f.write(f"Vulnerabilities Found ({len(self.results['nuclei_results'])}):\n")
                    f.write("\n".join(self.results['nuclei_results']) + "\n\n")
                else:
                    f.write("No vulnerabilities found or Nuclei scan failed.\n\n")

                # Nikto
                f.write(f"Web Server Scan Results (Nikto):\n")
                f.write(f"{'-'*30}\n")
                if self.results["nikto_results"]:
                    f.write(f"Issues Found ({len(self.results['nikto_results'])}):\n")
                    f.write("\n".join(self.results['nikto_results']) + "\n\n")
                else:
                    f.write("No issues found or Nikto scan failed.\n\n")

            self.log(f"Final report saved to {report_file}", level="SUCCESS")
        except Exception as e:
            self.log(f"Failed to save report: {str(e)}", level="ERROR")

    def run(self):
        """Execute full reconnaissance workflow."""
        self.print_banner()
        start_time = datetime.now()
        self.log(f"Starting reconnaissance for '{self.target}' at {start_time.strftime('%Y-%m-%d %H:%M:%S')}", level="INFO")

        self.whois_lookup()
        self.nslookup_lookup()
        self.port_scanning()
        self.subdomain_enumeration()
        self.directory_enumeration()
        self.nuclei_scan()
        self.nikto_scan()
        self.save_report()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.log(f"Reconnaissance completed in {duration:.2f} seconds at {end_time.strftime('%Y-%m-%d %H:%M:%S')}", level="SUCCESS")


def main():
    parser = argparse.ArgumentParser(description="CyberSift: WHOIS, NSLOOKUP, Nmap, Subfinder, Amass, Sublist3r, Dirb, Nuclei, and Nikto Scanner")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", default="Recon_output", help="Output directory (default: Recon_output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    valid_tlds = ('.com', '.org', '.net', '.io', '.edu', '.gov', '.co', '.app')
    if not any(args.target.endswith(tld) for tld in valid_tlds) and '.' not in args.target:
        print("[!] Error: Please provide a valid domain (e.g., example.com)")
        return

    recon = CyberSift(args.target, args.output, verbose=args.verbose)
    recon.run()


if __name__ == "__main__":
    main()
