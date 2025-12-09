# 🕵️‍♂️ Network Reconnaissance Agent

> **Automated Network Discovery & Moodle Hunter**
>
> *Identify hosts, scan ports, fingerprint services, and discover hidden web applications with a single command.*

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

---

## 🚀 Overview

**Network Reconnaissance Agent** is a specialized, lightweight network scanner designed for rapid environment assessment. Originally built to hunt for **Moodle** exam servers in local subnets, it has evolved into a general-purpose reconnaissance tool capable of:
*   **Auto-detecting** local network ranges.
*   **Identifying** live hosts and their vendors (via MAC address).
*   **Fingerprinting** web technologies (Apache, IIS, PHP, Moodle).
*   **Brute-forcing** common admin paths.

It is the perfect tool for when you plug into a new network and need to answer: *"Where is the server?"*

## ✨ Key Features

- **🧠 Smart Auto-Discovery**: No need to type IP ranges. The agent detects your subnet (`/24`) automatically.
- **🔍 Deep Service Fingerprinting**: Goes beyond port checking. It analyzes HTTP headers and HTML content to identify:
    - **CMS**: Moodle, WordPress, etc.
    - **Server**: Apache, Nginx, IIS.
    - **Lang**: PHP, ASP.NET.
- **📡 Host & Vendor Identification**: Resolves MAC addresses to manufactures (e.g., *Raspberry Pi*, *TP-Link*, *Dell*) to help physically locate devices.
- **🛡️ Resilience**:
    - **Multi-Path Fallback**: If `/moodle/` is 404, it checks `/`, `/admin/`, and `/login/` automatically.
    - **SSL/TLS**: Automatically handles self-signed certificates without complaining.
- **⚡ High Performance**: Uses **concurrent threading** for blazing fast scans.

## 🛠️ Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Hao-Tec/NetworkReconAgent.git
    cd NetworkReconAgent
    ```

2.  **Set up Virtual Environment**
    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # Linux/Mac
    source .venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Usage

### 🟢 Zero-Config Scan (Recommended)
Simply run the script. It will detect your network and hunt for Moodle by default.
```bash
python main.py
```

### 🎯 Targeted Scan
Search for a specific path on a specific subnet.
```bash
python main.py --subnet 192.168.1.0/24 --path /admin_panel/
```

### ⚙️ Custom Ports
Scan non-standard ports (e.g., 8080, 8888, 9000).
```bash
python main.py --ports 80,443,8080,9000
```

## 📊 Sample Output

```text
╔══════════════════════════════════════════╗
║      Network Reconnaissance Agent        ║
║      Moodle / Web Service Finder         ║
╚══════════════════════════════════════════╝

[*] Auto-detecting local network... 192.168.10.0/24
[1] Discovering hosts...
[+] Found 2 live hosts.
    - 192.168.10.2  [5C:4D:BF:5E:DD:80] (TP-Link)
    - 192.168.10.40 [AA:BB:CC:DD:EE:FF] (Dell)

[2] Scanning ports and fingerprinting...
[SUCCESS] Found SERVICE at http://192.168.10.2:80/moodle/ (Status: 200)
          Detected: Moodle 4.1, Apache/2.4, PHP/8.1

[SUMMARY] Targets Found: 1
 -> http://192.168.10.2:80/moodle/ [Status: 200] | Tech: Moodle (Content)
```

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## 📄 License
Destributed under the MIT License. See `LICENSE` for more information.
