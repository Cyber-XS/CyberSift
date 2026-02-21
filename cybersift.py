#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import sys
import subprocess

R = '\033[91m'  # Red
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
B = '\033[38;2;28;28;240m' # Blue
C = '\033[38;2;0;255;255m' # Orrange
W = '\033[0m'   # Reset (White/Default)

def clear_screen():
    os.system('clear')

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
               ░░░░░░   Great Power Comes with Great Responsibilities.

    """ + W)

print_banner()
print(G + "=" * 100 + W)

def main_menu():
    while True:
        print(" 🌐 [1] Host Discovery")
        print(" 🖥️ [2] Host Fingerprinting")
        print(" 🌍 [3] Subdomain Enumeration")
        print(" 🕵️ [4] Information Gathering")
        print(" 🛡️ [5] Vulnerability Scanning")
        print(" 🤖 [6] Hacking AI")
        print(" ❌ [0] Exit")

        choice = input(C + "\n ✨ What you want to do Today ⮞ " + W).strip()

        if choice == "1":
            print("\n[+] Host Discovery Starting...")
            host_discovery()
        elif choice == "2":
            print("\n[+] Host Fingerprinting Starting...")
            host_fingerprinting()
        elif choice == "3":
            print("\n[+] Subdomain Enumeration Starting...")
            subdomain_enumeration()
        elif choice == "4":
            print("\n[+] Information Gathering Starting...")
            information_gathering()
        elif choice == "5":
            print("\n[+] Vulnerability Scanning Starting...")
            vulnerability_scanning()
        elif choice == "6":
            print("\n[+] Hacking AI Starting...")
            hacking_ai()
        elif choice == "0":
            print("\n[+] Power Off CyberSift")
            sys.exit(0)
        else :
            time.sleep(1)

def host_discovery():
    print(B + "Host Discovery running =>> Arp-Scan" + W)
    cmd = ["sudo", "arp-scan", "--localnet"]

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
            print("[✓] Scan finished successfully")
        else:
            print(f"[!] Finished with exit code {exit_code}")


    except FileNotFoundError:
        print("[!] 'arp-scan' is not installed")
        print("    sudo apt install arp-scan          # Debian / Ubuntu")
        print("    sudo dnf install arp-scan          # Fedora")
        print("    sudo pacman -S arp-scan            # Arch")

    except PermissionError:
        print("[!] Permission denied (wrong sudo password?)")

    print(G + "=" * 100 + W)

def host_fingerprinting():
    print(B + "Host Fingerprinting running =>> Nmap" + W)
    cmd = ["sudo", "nmap", input("Enter Host: "), "-sS", "-sV", "-p-", "-v", "-O"]

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
            print("[✓] Scan finished successfully")
        else:
            print(f"[!] Finished with exit code {exit_code}")


    except FileNotFoundError:
        print("[!] 'nmap' is not installed")
        print("    sudo apt install nmap          # Debian / Ubuntu")
        print("    sudo dnf install nmap          # Fedora")
        print("    sudo pacman -S nmap            # Arch")

    except PermissionError:
        print("[!] Permission denied (wrong sudo password?)")

    print(G + "=" * 100 + W)

def subdomain_enumeration():
    print(B + "Subdomain Enumeration =>> Subfinder" + W)
    cmd = ["subfinder", "-d", input("Enter Host: "), "-all"]

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
            print("[✓] Scan finished successfully")
        else:
            print(f"[!] Finished with exit code {exit_code}")


    except FileNotFoundError:
        print("[!] 'Subfinder' is not installed")
        print("    sudo apt install subfinder          # Debian / Ubuntu")
        print("    sudo dnf install subfinder          # Fedora")
        print("    sudo pacman -S subfinder            # Arch")

    except PermissionError:
        print("[!] Permission denied (wrong sudo password?)")

    print(G + "=" * 100 + W)

def information_gathering():
    print(B + "Information Gathering =>> Spiderfoot" + W)
    cmd = ["spiderfoot", "-s", input("Enter Host : "), "-u", "all", "-max-threads", "100"]

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
            print("[✓] Scan finished successfully")
        else:
            print(f"[!] Finished with exit code {exit_code}")


    except FileNotFoundError:
        print("[!] 'Spiderfoot' is not installed")
        print("    sudo apt install spiderfoot          # Debian / Ubuntu")
        print("    sudo dnf install spiderfoot          # Fedora")
        print("    sudo pacman -S spiderfoot            # Arch")

    except PermissionError:
        print("[!] Permission denied (wrong sudo password?)")

    print(G + "=" * 100 + W)

def vulnerability_scanning():
    print(B + "Vulnerability Scanning =>> Nuclei" + W)
    cmd = ["nuclei", "-u", input("Enter Host : "), "-as", "-dast", "-headless", "-code", "-severity", "critical,high,medium"]

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
            print("[✓] Scan finished successfully")
        else:
            print(f"[!] Finished with exit code {exit_code}")


    except FileNotFoundError:
        print("[!] 'Nuclei' is not installed")
        print("    sudo apt install nuclei          # Debian / Ubuntu")
        print("    sudo dnf install nuclei          # Fedora")
        print("    sudo pacman -S nuclei            # Arch")

    except PermissionError:
        print("[!] Permission denied (wrong sudo password?)")

    print(G + "=" * 100 + W)

def hacking_ai():
    print(B + "Hacking AI =>> Hivemind Heretic" + W)
    print("Commands: Type '/bye' to return to menu")
    cmd = ["ollama", "run", "hivemind-heretic"]

    try:
        subprocess.run(cmd)

    except FileNotFoundError:
        print("[!] 'Hivemind Heretic' is not installed")
        print("    sudo apt install curl          # Debian / Ubuntu")
        print("    sudo dnf install curl          # Fedora")
        print("    sudo pacman -S curl            # Arch")
        print("    curl -fsSL https://ollama.com/install.sh | sh")
        print("    ollama create hivemind-heretic -f Modelfile")

    print(G + "=" * 100 + W)


if __name__ == "__main__":
    main_menu()
