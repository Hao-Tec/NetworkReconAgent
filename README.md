# 🕵️‍♂️ Network Reconnaissance Agent v2.4.0 ULTIMATE

> **Enterprise-Grade Network Discovery & Multi-Protocol Scanner**
>
> _Lightning-fast network reconnaissance with async I/O, multi-protocol detection, and professional reporting._

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production-success?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.4.0-orange?style=for-the-badge)

---

## 🚀 Overview

**Network Reconnaissance Agent** is a professional-grade network scanner designed for security auditors, penetration testers, and network administrators. With **v2.4.0**, it has evolved from a simple Moodle hunter into a comprehensive reconnaissance platform featuring:

- **⚡ Async I/O**: 20-50x faster scanning with `--async` mode
- **🔌 Multi-Protocol Detection**: SSH, FTP, MySQL, Redis, PostgreSQL, MongoDB, and more
- **🎯 Smart Fingerprinting**: CMS detection (Moodle, WordPress, Canvas), version extraction
- **📊 Professional Reporting**: JSON/CSV export for integration with other tools
- **🛡️ Enterprise Reliability**: Retry logic, connection pooling, structured logging

---

## ✨ Key Features

### v2.4.0 ULTIMATE Updates

#### 🚀 **Speed Revolution**

- **Async I/O Mode**: Use `--async` for 20-50x faster scans (powered by `aiohttp`)
- **Connection Pooling**: Reuses TCP connections for 3-5x HTTP performance boost
- **Smart Retry Logic**: Exponential backoff (0.5s → 1s → 2s) for transient failures
- **Configurable Concurrency**: `--max-workers` to tune for your network (default: 20)

#### 🔌 **Multi-Protocol Service Detection**

- **SSH** (port 22): Banner grabbing with version detection
- **FTP** (port 21): Service identification
- **MySQL/MariaDB** (3306, 3307): Protocol handshake parsing + version extraction
- **PostgreSQL** (5432): Database detection
- **Redis** (6379): Active INFO probing with version
- **MongoDB** (27017): NoSQL database detection
- **Microsoft SQL Server** (1433): Enterprise database detection
- **RabbitMQ** (5672): AMQP message broker detection
- **+11 more protocols** with intelligent fallback

#### 📊 **Professional Reporting**

- **JSON Export**: `--output results.json` for machine-readable data
- **CSV Export**: `--output scan.csv` for Excel/spreadsheet import
- **Structured Data**: Host info, MAC addresses, services, ports, fingerprints

#### 🛠️ **Advanced Configuration**

- **Custom Timeouts**: `--timeout <seconds>` for slow networks (default: 3s)
- **Retry Control**: `--retries <N>` adjustable failure recovery (default: 3)
- **Debug Logging**: `--log-file scan.log` for troubleshooting
- **Thread Control**: `--max-workers <N>` optimize concurrency

### Core Features (v2.0+)

- **🎨 Visual Excellence**: Matrix rain animation, Rich progress bars (full-width blocks)
- **⚡ ARP Scanning**: Lightning-fast local network discovery (fallback to Ping)
- **🔢 Flexible Port Scanning**: Ranges (`--ports 100-200`), lists, or `--all-ports`
- **🕸️ Deep Web Enumeration**: Auto-detects Moodle, WordPress, Canvas, Blackboard
- **🧠 Smart Auto-Discovery**: Automatically detects local subnet (`/24`)
- **📡 MAC Vendor Resolution**: 270+ OUI entries (ZTE, Huawei, Cisco, Apple, Samsung, etc.)
- **🛡️ SSL/TLS Support**: Handles self-signed certificates gracefully

---

## 📥 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Hao-Tec/NetworkReconAgent.git
cd NetworkReconAgent
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies:**

- `requests` - HTTP client with retry support
- `rich` - Terminal UI and progress bars
- `colorama` - Cross-platform colored output
- `psutil` - Network interface detection
- `scapy` - ARP scanning (optional, requires admin)
- `aiohttp` - Async HTTP (optional, for `--async` mode)

### 3. (Optional) Install Scapy for ARP Scanning

> ⚠️ **Requires Administrator/Root privileges**

**Windows:**

```bash
pip install scapy
# Run PowerShell/CMD as Administrator
```

**Linux/macOS:**

```bash
sudo pip install scapy
sudo python main.py
```

---

## 🎯 Usage

### Quick Start

```bash
# Basic scan (auto-detects local network)
python main.py

# Scan specific subnet
python main.py --subnet 192.168.1.0/24

# Custom ports
python main.py --ports 22,80,443,3306,5432,6379

# Port range
python main.py --ports 1-1000
```

### ⚡ Async Mode (Recommended for Speed)

```bash
# Enable async I/O for 20-50x speed boost
python main.py --async

# Async with custom concurrency
python main.py --async --max-workers 50

# Full power: async + large concurrency
python main.py --async --max-workers 100 --timeout 5
```

### 📊 Exporting Results

```bash
# JSON format (best for automation)
python main.py --async --output scan_results.json

# CSV format (best for Excel)
python main.py --output network_audit.csv

# With logging for debugging
python main.py --async --output results.json --log-file debug.log
```

### 🔧 Advanced Configuration

```bash
# Slow network? Increase timeout
python main.py --timeout 10 --retries 5

# Scan all 65,535 ports (slow!)
python main.py --all-ports --async

# Hunt for specific service
python main.py --path /admin/ --async

# Combine everything
python main.py --async \
  --subnet 10.0.0.0/24 \
  --ports 22,80,443,3306,5432,6379,27017 \
  --timeout 5 \
  --max-workers 50 \
  --output full_scan.json \
  --log-file scan.log
```

---

## 📋 Command-Line Arguments

| Argument            | Description                                  | Default                                     |
| ------------------- | -------------------------------------------- | ------------------------------------------- |
| `--subnet <CIDR>`   | Target subnet (e.g., `192.168.0.0/24`)       | Auto-detected                               |
| `--ports <LIST>`    | Ports to scan (e.g., `80,443` or `100-200`)  | `80,443,8080,8000,8888,3000,5000,8443,9000` |
| `--all-ports`       | Scan all ports (1-65535) ⚠️ Very slow        | Disabled                                    |
| `--path <PATH>`     | URL path to check (e.g., `/moodle/`)         | `/moodle/`                                  |
| `--async`           | **Enable async I/O (20-50x faster)**         | Disabled                                    |
| `--timeout <SEC>`   | HTTP request timeout in seconds              | `3`                                         |
| `--retries <N>`     | Number of retry attempts for failed requests | `3`                                         |
| `--max-workers <N>` | Maximum concurrent workers                   | `20`                                        |
| `--output <FILE>`   | Save report (`.json` or `.csv`)              | None                                        |
| `--log-file <PATH>` | Debug log file path                          | None                                        |
| `--debug`           | Show full error tracebacks                   | Disabled                                    |

---

## 📊 Output Examples

### Live Hosts Table

```
┌───────────────┬──────────────────────────┐
│ IP Address    │ MAC Address / Vendor     │
├───────────────┼──────────────────────────┤
│ 192.168.10.1  │ [98:BA:5F:XX:XX:XX] (TP-Link) │
│ 192.168.10.2  │ [5C:4D:BF:XX:XX:XX]      │
│ 192.168.10.10 │ [B8:27:EB:XX:XX:XX] (Raspberry Pi) │
└───────────────┴──────────────────────────┘
```

### Service Detection

```
[SUCCESS] Found SERVICE at http://192.168.10.2:80/moodle/ (Status: 200)
          Detected: Apache/2.4.41, PHP/7.4.3, Moodle 3.9.2

[INFO] Found SSH: SSH-2.0-OpenSSH_8.2p1 Ubuntu at 192.168.10.10:22
[INFO] Found MySQL/MariaDB: 5.7.38-0ubuntu0.18.04.1 at 192.168.10.20:3306
[INFO] Found Redis: 6.2.7 at 192.168.10.30:6379
```

### JSON Export Format

```json
{
  "scan_info": {
    "subnet": "192.168.10.0/24",
    "ports": "80,443,8080,3306,6379",
    "target_path": "/moodle/"
  },
  "hosts": [
    {
      "ip": "192.168.10.2",
      "mac": "[5C:4D:BF:XX:XX:XX]",
      "services": [
        {
          "port": 80,
          "url": "http://192.168.10.2:80/moodle/",
          "status": 200,
          "fingerprint": "Apache/2.4.41, Moodle 3.9.2"
        }
      ]
    }
  ]
}
```

---

## ⚙️ Architecture

```
NetworkReconAgent/
├── main.py              # CLI entry point
├── scanner.py           # Core scanning logic
│   ├── HostDiscovery    # ARP/Ping host discovery
│   ├── PortScanner      # TCP port scanning
│   ├── ServiceVerifier  # Sync HTTP verification
│   ├── AsyncServiceVerifier  # Async HTTP (aiohttp)
│   ├── BannerGrabber    # Multi-protocol detection
│   └── MacScanner       # MAC address resolution
├── reporter.py          # JSON/CSV export
├── banner.py            # Startup animations
└── requirements.txt     # Python dependencies
```

**Scanning Flow:**

1. **Host Discovery**: ARP scan (or Ping fallback) finds live hosts
2. **Port Scanning**: TCP connect to detect open ports
3. **Service Verification**:
   - Try HTTP/HTTPS first (web services)
   - Fall back to banner grabbing (SSH, MySQL, etc.)
4. **Fingerprinting**: Extract versions, CMS, technologies
5. **Reporting**: Display tables, export JSON/CSV

---

## 🔒 Security & Ethics

> ⚠️ **DISCLAIMER**: This tool is for **authorized testing only**. Unauthorized network scanning may be illegal in your jurisdiction.

**Responsible Use:**

- ✅ Only scan networks you own or have written permission to test
- ✅ Respect rate limits and avoid DoS conditions
- ✅ Follow your organization's security policies
- ✅ Use `--max-workers` conservatively on production networks

**This tool is designed for:**

- Internal security audits
- Penetration testing engagements
- Network inventory management
- DevOps monitoring
- Educational purposes

---

## 🐛 Troubleshooting

### "Permission Error: Access Denied"

**Cause**: ARP scanning requires administrator privileges.

**Solution**:

- **Windows**: Run PowerShell/CMD as Administrator
- **Linux/macOS**: Use `sudo python main.py`
- **Alternative**: Tool will automatically fall back to Ping (slower but no admin needed)

### "Async mode requires aiohttp"

**Cause**: `aiohttp` not installed.

**Solution**:

```bash
pip install aiohttp
```

### Slow Scanning Speed

**Solutions**:

1. **Enable async mode**: `--async` (20-50x faster)
2. **Increase workers**: `--max-workers 50`
3. **Reduce timeout**: `--timeout 2` (risky for slow networks)
4. **Scan fewer ports**: Focus on common ports instead of `--all-ports`

### False Positives

**Issue**: Tool reports services that don't exist.

**Causes**:

- Firewalls returning generic "200 OK" for any URL
- Captive portals (hotel WiFi, corporate networks)

**Solutions**:

- Tool has built-in wildcard detection
- Check "partial matches" table for root-only responses
- Use `--debug` to see HTTP responses

---

## 📈 Performance Benchmarks

**Test Environment**: 192.168.10.0/24 (254 possible hosts), 12 live hosts, 9 common ports

| Mode                | Time   | Speedup      |
| ------------------- | ------ | ------------ |
| **Sync (default)**  | 8m 42s | 1x           |
| Sync + 50 workers   | 5m 18s | 1.6x         |
| **Async (default)** | 22s    | **23.7x** ⚡ |
| Async + 100 workers | 18s    | 29x          |

> 💡 **Tip**: For large networks (`/16` or bigger), async mode is **essential**.

---

## 🔮 Roadmap (Future Versions)

### v2.5.0 (Planned)

- 📊 HTML report generation with interactive charts
- 💾 Save/Resume functionality for large scans
- 🎨 Interactive TUI dashboard
- 🔍 Passive network monitoring mode

### v3.0.0 (Vision)

- 🌐 Distributed scanning (multiple agents)
- 🗄️ Database backend for historical data
- 🔌 Plugin system for custom protocol detectors
- 📡 REST API for integration

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Coding Standards:**

- Maintain 10/10 Pylint score
- Add docstrings to new functions
- Update README for new features
- Test on Windows and Linux

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Rich** library for beautiful terminal UI
- **Scapy** for powerful packet crafting
- **aiohttp** for async HTTP performance
- The security research community

---

## 📞 Contact

**Author**: AbdulWaheed Habeeb  
**GitHub**: [@Hao-Tec](https://github.com/Hao-Tec)  
**Repository**: [NetworkReconAgent](https://github.com/Hao-Tec/NetworkReconAgent)

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Made with ❤️ for the security community

</div>
