# 🕵️‍♂️ CyberSift — The All-in-One Reconnaissance Toolkit

CyberSift is a powerful, automated reconnaissance and vulnerability scanning tool designed for bug bounty hunters, penetration testers, and cybersecurity researchers.
It intelligently integrates multiple industry-standard tools into a single streamlined workflow to make information gathering faster, smarter, and more efficient.

## ⚙️ Features

🔍 **Subdomain Enumeration** — Uses subfinder, amass, and sublist3r for exhaustive subdomain discovery.

🌐 **Port & Service Scanning** — Leverages nmap for deep network insights and service detection.

🗂️ **Directory Bruteforcing** — Employs dirb and ffuf to uncover hidden directories and endpoints.

🧩 **Vulnerability Scanning** — Integrates nuclei for automated template-based vulnerability detection.

⚡ **Customizable Automation** — Modular structure lets you enable or disable tools as needed.

📊 **Clean Output & Logging** — Consolidated, well-formatted reports to simplify your analysis workflow.

## 🚀 Why CyberSift?

No more juggling multiple recon tools or writing endless bash scripts — CyberSift sifts through data intelligently, automating the boring parts and letting you focus on what matters most — finding vulnerabilities.

## 🧠 Tools Integrated

nmap, subfinder, amass, dirb, ffuf, nuclei, sublist3r, and more


**Follow the steps below to set up and run the CyberSift on your Linux machine:**

1️⃣ Clone the Repository

Open a terminal and run:

    git clone https://github.com/Cyber-XS/CyberSift.git
    cd CyberSift
    chmod +x arch.sh debian.sh cybersift.sh

Install Requirments for Debian Based Distros

    ./debian.sh

Install Requirments for Arch Based Distros

    ./arch.sh

Run CyberSift

    ./cybersift <domain_name>




