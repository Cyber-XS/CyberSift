#!/usr/bin/env python3

import subprocess
import os
import argparse
from datetime import datetime

class CyberSift:
    VERSION = "1.0.0"

    def __init__(self, target, output_dir="Recon_output", verbose=False):
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
            "ports": "",
            "subdomains": [],
            "directories": [],
            "ffuf_results": [],
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
        """.format(self.VERSION)
        print(banner)

    def run_command(self, cmd, output_file=None):
        """Execute a shell command and save output."""
        self.log(f"Executing command: {cmd}", level="DEBUG")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            if result.stderr and self.verbose:
                for line in result.stderr.strip().splitlines():
                    if line.strip():
                        self.log(f"stderr: {line}", level="WARNING")
            output = result.stdout.strip()

            if output_file:
                file_path = os.path.join(self.output_dir, output_file)
                with open(file_path, "w") as f:
                    f.write(output + "\n")
                self.log(f"Output saved to {file_path}", level="INFO")

            return output
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after 600s: {cmd}"
            self.log(error_msg, level="ERROR")
            return None
        except Exception as e:
            error_msg = f"Exception in command '{cmd}': {str(e)}"
            self.log(error_msg, level="ERROR")
            return None

    def port_scanning(self):
        """Run Nmap for basic port scanning on the target domain."""
        self.log(f"Starting port scanning for {self.target}...", level="INFO")

        nmap_file = "nmap.txt" #Nmap
        nmap_cmd = f"nmap -sS {self.target} -oN {os.path.join(self.output_dir, nmap_file)}"

        output = self.run_command(nmap_cmd, nmap_file)
        self.results["ports"] = output if output else ""

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

        subfinder_file = "subfinder.txt" #Subfinder
        subfinder_cmd = f"subfinder -d {self.target} -o {os.path.join(self.output_dir, subfinder_file)} -silent"
        
        subfinder_output = self.run_command(subfinder_cmd, subfinder_file)
        if subfinder_output:
            subfinder_subdomains = [line.strip() for line in subfinder_output.splitlines() if line.strip() and not line.startswith("[")]
            subdomains.extend(subfinder_subdomains)
            self.log(f"Found {len(subfinder_subdomains)} subdomains with Subfinder.", level="SUCCESS")
            if self.verbose and subfinder_subdomains:
                preview = subfinder_subdomains[:10]
                self.log("Sample Subfinder subdomains:\n" + "\n".join(preview) + ("\n..." if len(subfinder_subdomains) > 10 else ""), level="INFO")
        else:
            self.log("Subfinder enumeration failed or no results.", level="WARNING")

        amass_file = "amass.txt" #Amass
        amass_cmd = f"amass enum -active -d {self.target} -o {os.path.join(self.output_dir, amass_file)} -silent"
        
        amass_output = self.run_command(amass_cmd, amass_file)
        if amass_output:
            amass_subdomains = [line.strip() for line in amass_output.splitlines() if line.strip() and not line.startswith("[")]
            subdomains.extend(amass_subdomains)
            self.log(f"Found {len(amass_subdomains)} subdomains with Amass.", level="SUCCESS")
            if self.verbose and amass_subdomains:
                preview = amass_subdomains[:10]
                self.log("Sample Amass subdomains:\n" + "\n".join(preview) + ("\n..." if len(amass_subdomains) > 10 else ""), level="INFO")
        else:
            self.log("Amass enumeration failed or no results.", level="WARNING")

        sublist3r_file = "sublist3r.txt" #Sublist3r
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

        # Combine and deduplicate subdomains
        subdomains = list(set(subdomains))  # Remove duplicates
        self.results["subdomains"] = subdomains
        self.log(f"Total unique subdomains found: {len(subdomains)}.", level="SUCCESS")
        if self.verbose and subdomains:
            preview = subdomains[:10]
            self.log("Sample combined subdomains:\n" + "\n".join(preview) + ("\n..." if len(subdomains) > 10 else ""), level="INFO")

    def directory_enumeration(self):
        """Run Dirb for directory enumeration with specified wordlist."""
        self.log(f"Starting directory enumeration for {self.target}...", level="INFO")

        dirb_file = "dirb.txt" #Dirb
        wordlist_path = "/usr/share/dirb/wordlists/common.txt"
        
        if not os.path.isfile(wordlist_path):
            self.log(f"Wordlist file not found: {wordlist_path}", level="ERROR")
            return

        dirb_cmd = f"dirb http://{self.target} {wordlist_path} -o {os.path.join(self.output_dir, dirb_file)} -S"
        
        dirb_output = self.run_command(dirb_cmd, dirb_file)
        directories = []

        if dirb_output:
            directories = [line.strip() for line in dirb_output.splitlines() if line.strip() and line.startswith("+ ")]
            directories = [line[2:].split(" ")[0] for line in directories]  # Extract URLs starting with "+"
            self.results["directories"] = directories
            self.log(f"Found {len(directories)} directories.", level="SUCCESS")
            if self.verbose and directories:
                preview = directories[:10]
                self.log("Sample directories:\n" + "\n".join(preview) + ("\n..." if len(directories) > 10 else ""), level="INFO")
        else:
            self.log("Directory enumeration failed or no results.", level="WARNING")
            self.results["directories"] = []

    def ffuf_enumeration(self):
        """Run ffuf for directory and file enumeration with specified wordlist."""
        self.log(f"Starting ffuf enumeration for {self.target}...", level="INFO")

        ffuf_file = "ffuf.txt" #Ffuf
        wordlist_path = "/usr/share/dirb/wordlists/common.txt"
        
        if not os.path.isfile(wordlist_path):
            self.log(f"Wordlist file not found: {wordlist_path}", level="ERROR")
            return

        ffuf_cmd = (
            f"ffuf -u http://{self.target}/FUZZ -w {wordlist_path} "
            f"-o {os.path.join(self.output_dir, ffuf_file)} -of csv"
        )
        
        ffuf_output = self.run_command(ffuf_cmd, ffuf_file)
        ffuf_results = []

        if ffuf_output:
            # Parse CSV output from ffuf
            lines = ffuf_output.splitlines()
            for line in lines[1:]:  # Skip header line
                if line.strip():
                    parts = line.split(",")
                    if len(parts) > 0:
                        ffuf_results.append(parts[0])  # Extract the 'input' field (FUZZ value)
            self.results["ffuf_results"] = ffuf_results
            self.log(f"Found {len(ffuf_results)} directories/files with ffuf.", level="SUCCESS")
            if self.verbose and ffuf_results:
                preview = ffuf_results[:10]
                self.log("Sample ffuf results:\n" + "\n".join(preview) + ("\n..." if len(ffuf_results) > 10 else ""), level="INFO")
        else:
            self.log("ffuf enumeration failed or no results.", level="WARNING")
            self.results["ffuf_results"] = []

    def nuclei_scan(self):
        """Run Nuclei for vulnerability scanning."""
        self.log(f"Starting Nuclei vulnerability scan for {self.target}...", level="INFO")

        nuclei_file = "nuclei.txt" #Nuclei
        nuclei_cmd = f"nuclei -u http://{self.target} -o {os.path.join(self.output_dir, nuclei_file)} -silent"
        
        nuclei_output = self.run_command(nuclei_cmd, nuclei_file)
        nuclei_results = []

        if nuclei_output:
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

        nikto_file = "nikto.txt" #Nikto
        nikto_cmd = f"nikto -h http://{self.target} -output {os.path.join(self.output_dir, nikto_file)} -Format txt"
        
        nikto_output = self.run_command(nikto_cmd, nikto_file)
        nikto_results = []

        if nikto_output:
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
                f.write(f"Verbose Mode: {self.results['verbose']}\n")
                f.write(f"\nPort Scanning Results:\n")
                f.write(f"{'-'*30}\n")
                if self.results["ports"]:
                    open_ports = [line for line in self.results["ports"].splitlines() if "/tcp" in line and "open" in line]
                    if open_ports:
                        f.write(f"Open Ports ({len(open_ports)}):\n")
                        f.write("\n".join(open_ports) + "\n")
                    else:
                        f.write("No open ports found.\n")
                else:
                    f.write("Port scanning failed or returned no output.\n")
                f.write(f"\nSubdomain Enumeration Results (Subfinder, Amass, and Sublist3r):\n")
                f.write(f"{'-'*30}\n")
                if self.results["subdomains"]:
                    f.write(f"Subdomains Found ({len(self.results['subdomains'])}):\n")
                    f.write("\n".join(self.results['subdomains']) + "\n")
                else:
                    f.write("No subdomains found or enumeration failed.\n")
                f.write(f"\nDirectory Enumeration Results (Dirb):\n")
                f.write(f"{'-'*30}\n")
                if self.results["directories"]:
                    f.write(f"Directories Found ({len(self.results['directories'])}):\n")
                    f.write("\n".join(self.results['directories']) + "\n")
                else:
                    f.write("No directories found or enumeration failed.\n")
                f.write(f"\nDirectory/File Enumeration Results (ffuf):\n")
                f.write(f"{'-'*30}\n")
                if self.results["ffuf_results"]:
                    f.write(f"Directories/Files Found ({len(self.results['ffuf_results'])}):\n")
                    f.write("\n".join(self.results['ffuf_results']) + "\n")
                else:
                    f.write("No directories/files found or ffuf enumeration failed.\n")
                f.write(f"\nVulnerability Scan Results (Nuclei):\n")
                f.write(f"{'-'*30}\n")
                if self.results["nuclei_results"]:
                    f.write(f"Vulnerabilities Found ({len(self.results['nuclei_results'])}):\n")
                    f.write("\n".join(self.results['nuclei_results']) + "\n")
                else:
                    f.write("No vulnerabilities found or Nuclei scan failed.\n")
                f.write(f"\nWeb Server Scan Results (Nikto):\n")
                f.write(f"{'-'*30}\n")
                if self.results["nikto_results"]:
                    f.write(f"Issues Found ({len(self.results['nikto_results'])}):\n")
                    f.write("\n".join(self.results['nikto_results']) + "\n")
                else:
                    f.write("No issues found or Nikto scan failed.\n")
            self.log(f"Final report saved to {report_file}", level="SUCCESS")
        except Exception as e:
            self.log(f"Failed to save report: {str(e)}", level="ERROR")

    def run(self):
        """Execute the Nmap, Subfinder, Amass, Sublist3r, Dirb, ffuf, Nuclei, and Nikto scan workflow."""
        self.print_banner()
        start_time = datetime.now()
        self.log(f"Starting reconnaissance for '{self.target}' at {start_time.strftime('%Y-%m-%d %H:%M:%S')}", level="INFO")

        self.port_scanning()
        self.subdomain_enumeration()
        self.directory_enumeration()
        self.ffuf_enumeration()
        self.nuclei_scan()
        self.nikto_scan()
        self.save_report()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.log(f"Reconnaissance completed in {duration:.2f} seconds at {end_time.strftime('%Y-%m-%d %H:%M:%S')}", level="SUCCESS")


def main():
    parser = argparse.ArgumentParser(description="CyberSift: Nmap, Subfinder, Amass, Sublist3r, Dirb, ffuf, Nuclei, and Nikto Scanner")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", default="Recon_output", help="Output directory (default: Recon_output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if not args.target.endswith(('.com', '.org', '.net', '.io', '.edu', '.gov')) and '.' not in args.target:
        print("[!] Error: Please provide a valid domain (e.g., example.com)")
        return

    recon = CyberSift(args.target, args.output, verbose=args.verbose)
    recon.run()


if __name__ == "__main__":
    main()