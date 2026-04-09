#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import sys
import subprocess

R  = '\033[91m'           # Red
G  = '\033[92m'           # Green
Y  = '\033[93m'           # Yellow
B  = '\033[38;2;28;28;240m'  # Blue
C  = '\033[38;2;0;255;255m'  # Cyan
P  = '\033[95m'           # Purple / Magenta
W  = '\033[0m'            # Reset

def clear_screen():
    os.system('clear')

def separator():
    print(G + "=" * 100 + W)

def run(cmd, tool_name):
    """Run a subprocess and stream output live."""
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        while True:
            line = process.stdout.readline()
            if line == "" and process.poll() is not None:
                break
            if line:
                sys.stdout.write(line)
                sys.stdout.flush()
        exit_code = process.wait()
        if exit_code == 0:
            print(G + "\n[✓] Finished successfully" + W)
        else:
            print(R + "\n[!] Finished with exit code {exit_code} + W")
    except FileNotFoundError:
        print(R + f"\n[!] '{tool_name}' is not installed." + W)
        print(Y + f"    Install it and try again." + W)
    except PermissionError:
        print(R + "[!] Permission denied" + W)


def prompt(msg):
    return input(C + f"\n ✨ {msg} ⮞ " + W).strip()


def print_banner():
    clear_screen()
    print(R + r"""
    
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
               ░░░░░░   _v2_

    """ + W)
    print(Y + "               Great Power Comes with Great Responsibilities.\n" + W)
    separator()

# WebApp Pentest Sub menus

# Information Gathering
def subdomain_enumeration():
    print(B +"\n[+] Subdomain Enumeration ⮞ subfinder + amass + sublist3r"+ W)
    target = prompt("Enter target domain")
    print(Y +"\n [1] subfinder\n [2] amass\n [3] sublist3r\n [0] Back"+ W)
    ch = prompt("Choose Tool")
    if ch == "1":
        run(["subfinder", "-d", target, "-all"], "subfinder")
    elif ch == "2":
        run(["amass", "enum", "-passive", "-d", target], "amass")
    elif ch == "3":
        run(["sublist3r", "-d", target], "sublist3r")
    separator()

def dns_enum():
    print(B +"\n[+] DNS Enumeration ⮞ dnsx / dig" + W)
    target = prompt("Enter target domain")
    print(Y +"\n [1] dnsx\n [2] dig (all records)\n [0] Back" + W)
    ch = prompt("Choose tool")
    if ch == "1":
        run(["dnsx", "-d", target, "-a", "-aaa", "-cname", "-mx", "-ns", "-txt"], "dnsx")
    elif ch == "2":
        run(["dig", target, "ANY"], "dig")
    separator()

def whois_lookup():
    print(B +"\n[+] WHOIS Lookup" + W)
    target = prompt("Enter target domain or IP")
    run(["whois", target], "whois")
    separator()

def tech_detection():
    print(B + "\n[+] Technology Detection ⮞ whatweb / wafw00f" + W)
    target = prompt("Enter target URL")
    print(Y + "\n [1] whatweb (tech stack)\n [2] wafw00f (WAF detection)\n [0] Back" + W)
    ch = prompt("Choose tool")
    if ch == "1":
        run(["whatweb", "-a", "3", target], "whatweb")
    elif ch == "2":
        run(["wafw00f", target], wafw00f)
    separator()

def web_crawling():
    print(B + "\n[+] Web Crawling ⮞ katana / gospider" + W)
    target = prompt("Enter target URL")
    print(Y + "\n [1] Katana\n [2] gospider\n [0] Back" + W)
    ch = prompt("Choose tool")
    if ch == "1":
        run(["katana", "-U", target, "-depth", "3"], katana)
    elif ch == "2":
        run(["gospider", "-s", target, "-d", "3"], "gospider")
    separator()

def information_gathering_menu():
    while True:
        print(P + "WebApp Pentest ⮞ Information Gathering\n" + W)
        print("[1] Subdomain Enumeration")
        print("[2] DNS Enumeration")
        print("[3] WHOIS Lookup")
        print("[4] Technology Detection")
        print("[5] Web Crawling")
        print("[0] Back")
        ch = prompt("Choose")
        if ch == "1": subdomain_enumeration()
        if ch == "2": dns_enum()
        if ch == "3": whois_lookup()
        if ch == "4": tech_detection()
        if ch == "5": web_crawling()
        if ch == "0": return
        else: time.sleep(0.5)

# Web Scanning
def dir_bruteforce():
    prin(B + "\n[+] Directory-Bruteforce ⮞ dirb / ffuf / gobuster   " + W)
    target = prompt(" Enter target URL")
    wordlist = prompt("Enter wordlisprint_bannert path (default: /usr/share/wordlists/dirb/common.txt)")
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    print(Y + "\n [1] dirb\n [2] ffuf\n [3] gobuster\n [0] Back" + W)
    ch = prompt("Choose tool")
    if ch == "1":
        run(["dirb", target, wordlist], "dirb")
    elif ch == "2":
        run(["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-mc", "200,301,302,403"], "ffuf")
    elif ch =="3":
        run(["gobuster", "dir", "-u", target, "-w", wordlist], "gobuster")
    separator()

def vuln_scan():
    print(B + "\n[+] Vulnerability Scanning ⮞ Nuclei" + W)
    target = prompt("Enter target URL")
    print(Y + "\n [1] DAST + headless(full)\n [2] Critical only\n [3] Custom Template path\n [0] Back" + W)
    ch = prompt("Choose scan type")
    if ch == "1":
        run(["nuclei", "-u", target, "-dast", "-headless", "-code", "-severity", "critical,high,medium"], "nuclei")
    elif ch == "2":
        run(["nuclei", "-u", target, "-severity", "critical"], "nuclei")
    elif ch == "3":
        run(["nuclei", "-u", target, "-t", tpath], "nuclei")
    separator()

def ssl_analysis():
    print(B + "\n[+] SSL/TLS Analysis ⮞ sslscan / testssl" + W)
    target = prompt("Enter target domain or IP")
    print(Y + "\n [1] sslscan\n [2] testssl\n [0] Back" + W)
    ch = prompt("Choose tool")
    if ch == "1":
        run(["sslscan", target], "sslscan")
    elif ch == "2":
        run(["testssl", target], "testssl")
    separator()

def cms_scan():
    print(B + "\n[+] CMS scanning ⮞ wpscan / droopescan" + W)
    target = prompt("Enter target URL")
    print(Y + "\n [1] wpscan (WordPress)\n [2] droopescan (Drupal/Joommla)\n [0] Back" + W)
    ch = prompt("Choose tool")
    if ch == "1":
        run(["wpscan", "--url", target, "--enumerate", "vp,vt,u"], "wpscan")
    elif ch == "2":
        run(["droopescan", "scan", "-u", target], "droopescan")
    separator()

def web_scanning_menu():
    while True:
        print(P + "WebApp Pentest ⮞ Web Scanning" + W)
        print("[1] Directory Brute-force")
        print("[2] Vulnerability Scanning")
        print("[3] SSL/TLS Analysis")
        print("[4] CMS Scanning")
        print("[0] Back")
        ch = prompt("Choose")
        if ch =="1": dir_bruteforce()
        elif ch =="2": vuln_scan()
        elif ch =="3": ssl_analysis()
        elif ch =="4": cms_scan()
        elif ch =="0": return
        else: time.sleep(0.5)

# Exploitation
def sql_injection():
    print(B + "\n[+] SQL Injection ⮞ sqlmap" + W)
    target = prompt("Enter target URL (witn parameter eg. http://target.com/page?id=1)")
    print(Y + "\n [1] Basic Scan\n [2] Full scan\n [3] Dump databases\n [0] Back" + W)
    ch = prompt("Choose")
    if ch =="1":
        run(["sqlmap", "-u", target, "--batch"], "sqlmap")
    elif ch =="2":
        run(["sqlmap", "-u", target, "--batch", "--level=5", "--risk=3"], "sqlmap")
    elif ch =="3":
        run(["sqlmap", "-u", target, "--batch", "--dbs"], "sqlmap")
    separator()

def xss_testing():
    print(B + "\n[+] XSS Testing ⮞ dalfox" + W)
    target = prompt("Enter target URL")
    print(Y + "\n [1] URL scan\n [2] Pipe mode\n [0]  Back" + W)
    ch = prompt("Choose")
    if ch =="1":
        run(["dalfox", "url", target], "dalfox")
    elif ch =="2":
        run(["dalfox", "pipe"], "dalfox")
    separator()

def param_fuzzing():
    print(B + "\n[+] Parameter fuzzing ⮞ arjun / ffuf" + W)
    target = prompt("Enter target URL")
    print(Y + "\n [1] arjun (parameter discovery)\n [2] ffuf (param fuzzing) [0] Back" + W)
    ch = prompt("Choose tool")
    if ch =="1":
        run(["arjun", "-u", target], "arjun")
    elif ch =="2":
        wordlist = prompt("Enter param wordlist path")
        run(["ffuf", "-u", f"{target}?FUZZ", "-w", wordlist, "ffuf"])
    separator()

def lif_rfi_testing():
    print(B + "\n[+] LFI/RFI Testing ⮞ nuclei templates" + W)
    target = prompt("Enter target URL")
    run(["nuclei", "-u", target, "-t", "fuzzing/lfi/", "-severity", "high,critical"], "nuclei")
    separator()

def exploitation_menu():
    while True:
        print(P + "WebApp Pentest ⮞ Exploitation" + W)
        print("[1] SQL Injection")
        print("[2] XSS Testing")
        print("[3] Parameter Fuzzing")
        print("[4] LFI/RFI Testing")
        print("[0] Back")
        ch = prompt("Choose")
        if ch =="1": sql_injection()
        elif ch =="2": xss_testing()
        elif ch =="3": param_fuzzing()
        elif ch =="4": lif_rfi_testing()
        elif ch =="0": return
        else: time.sleep(0.5)

# Authentication Testing
def login_bruteforce():
    print(B + "\n[+] Login-Bruteforce ⮞ hydra / medusa" + W)
    target = pprompt("Enter target IP or URL")
    print(Y + "\n [1] hydra\n [2] medusa\n [0] Back" + W)
    ch = prompt("Choose tool")
    if ch =="1":
        userlist = prompt("Enter username list path")
        passlist = prompt("Enter password list path")
        form_path = prompt("Enter login form path (eg. /login.php)")
        run(["hydra", "-L", userlist, "-p", passlist, target, "http-post-form", f"{form_path}:user=^USER^&pass=^PASS^:F=incorrect"], "hydra")
    elif ch == "2":
        userlist = prompt("Enter username list path")
        passlist = prompt("Enter password list path")
        run(["hydra", "-L", userlist, "-P", passlist, "ssh://"+target], "hydra")
    elif ch == "3":
        userlist = prompt("Enter username list path")
        passlist = prompt("Enter password list path")
        run(["medusa", "-H", target, "-U", userlist, "-P", passlist, "-M", "http"], "medusa")
    separator()

def auth_testing_menu():
    while True:
        print("[1] Login Bruteforce")
        print("[0] Back")
        ch = prompt("Choose")
        if ch =="1": login_bruteforce()
        elif ch =="0": return
        else: time.sleep(0.5)
    
# WebApp Pentest Root Menu
def webapp_pentest_menu():
    while True:
        print(P + "WebApp Pentest\n" + W)
        print("[1] Information Gathering")
        print("[2] Web Scanning")
        print("[3] Exploitation")
        print("[4] Authentication Testing")
        print("[0] Back to Main Menu")
        ch = prompt("Choose")
        if ch =="1": information_gathering_menu()
        elif ch =="2": web_scanning_menu()
        elif ch =="3": exploitation_menu()
        elif ch =="4": auth_testing_menu()
        elif ch =="0": return
        else: time.sleep(0.5)

# Network Pentest
def host_discovery():
    print(B + "\n[+] Host Discovery ⮞ arp-scan" + W)
    run(["sudo", "arp-scan", "--localnet"], "arp-scan")
    separator()

def host_fingerprinting():
    print(B + "\n[+] Host Fingerprinting ⮞ nmap" + W)
    target = prompt("Enter target IP or range")
    run(["sudo", "nmap", target, "-sS", "-sV", "-p-", "-v"], "nmap")
    separator()

def info_gathering():
    print(B + "\n[+] Information Gathering ⮞ spiderfoot" + W)
    target = prompt("Enter target")
    run(["spiderfoot", "-s", target, "-u", "all", "-max-threads", "100"], "spiderfoot")
    separator()

def network_pentest_menu():
    while True:
        print(P + "Network Pentest\n" + W)
        print("[1] Host Discovery")
        print("[2] Host Fingerprinting")
        print("[3] Information gathering")
        print("[0] Back to Main Menu")
        ch = prompt("Choose")
        if ch =="1": host_discovery()
        elif ch =="2": host_fingerprinting()
        elif ch =="3": info_gathering()
        elif ch =="0": return
        else: time.sleep(0.5)

# HackAI
def hacking_ai():
    print(B + "\n[+] Hacking AI ⮞ Hivemind Heretic (ollama)" + W)
    print(Y + "    Type '/bye' to return to menu\n" + W)
    try:
        subprocess.run(["ollama", "run", "hivemind-heretic"])
    except FileNotFoundError:
        print(R + "\n[!] 'ollama' or 'hivemind-heretic' model is not installed." + W)
        print(Y + """
    Install steps:
      curl -fsSL https://ollama.com/install.sh | sh
      curl -L -o Qwen3-8B-Hivemind-Inst-Hrtic-Ablit-Uncensored-Q8_0.gguf \\
        "https://huggingface.co/DavidAU/Qwen3-8B-Hivemind-Instruct-Heretic-Abliterated-Uncensored-NEO-Imatrix-GGUF/resolve/main/Qwen3-8B-Hivemind-Inst-Hrtic-Ablit-Uncensored-Q8_0.gguf?download=true"
      ollama create hivemind-heretic -f Modelfile
        """ + W)
    separator()
 
def hackai_menu():
    while True:
        print(P + "  [3] HackAI\n" + W)
        print("   🤖 [1] Hacking AI (Hivemind Heretic)")
        print("   🔙 [0] Back to Main Menu")
        ch = prompt("Choose")
        if   ch == "1": hacking_ai()
        elif ch == "0": return
        else: time.sleep(0.5)
 
# Main Menu
def main_menu():
    while True:
        print_banner()
        print("[1] WebApp Pentest")
        print("[2] Network Pentest")
        print("[3] HackAI")
        print("[0] Exit")
        ch = prompt("What you want to do Today")
        if   ch == "1": webapp_pentest_menu()
        elif ch == "2": network_pentest_menu()
        elif ch == "3": hackai_menu()
        elif ch == "0":
            print(G + "\n[+] Power Off CyberSift\n" + W)
            sys.exit(0)
        else:
            time.sleep(0.5)
 
 
if __name__ == "__main__":
    main_menu()
