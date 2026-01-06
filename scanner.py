# pylint: disable=duplicate-code,too-many-lines
"""Scanner utilities for host discovery, MAC lookup and simple port scanning."""

import ipaddress
import socket
import subprocess
import platform
import concurrent.futures
import re
import uuid
import functools
import asyncio
from typing import List, Tuple

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import psutil
except ImportError:
    psutil = None

try:
    # Check if scapy is available without fully loading it (avoids npcap issues)
    # pylint: disable=import-error
    import importlib.util

    HAS_SCAPY = importlib.util.find_spec("scapy") is not None
except Exception:  # pylint: disable=broad-exception-caught
    HAS_SCAPY = False

# Suppress InsecureRequestWarning from urllib3/requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Pre-compile ANSI escape code regex for performance
RE_ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def _strip_ansi(text: str) -> str:
    """Removes ANSI escape codes from text to prevent Terminal Injection."""
    return RE_ANSI_ESCAPE.sub('', text)


@functools.lru_cache(maxsize=512)
def _get_vendor_from_mac(mac_prefix: str) -> str:
    """
    Cached vendor lookup by MAC address prefix (OUI).
    Covers 80+ common network equipment manufacturers.
    Returns vendor name or empty string.

    Performance: Dict lookup is O(1), lru_cache ensures repeated lookups are instant.
    """
    # Comprehensive OUI database - Top 80+ manufacturers
    # Format: First 3 octets (OUI) -> Vendor Name
    vendors = {
        # Raspberry Pi / Single Board Computers
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        # Apple
        "00:03:93": "Apple",
        "00:05:02": "Apple",
        "00:0A:27": "Apple",
        "00:0A:95": "Apple",
        "00:0D:93": "Apple",
        "00:1C:B3": "Apple",
        "00:1E:C2": "Apple",
        "00:21:E9": "Apple",
        "00:25:00": "Apple",
        "3C:06:30": "Apple",
        "A4:83:E7": "Apple",
        "AC:BC:32": "Apple",
        # Samsung
        "00:12:FB": "Samsung",
        "00:15:99": "Samsung",
        "00:1A:8A": "Samsung",
        "00:21:4C": "Samsung",
        "00:26:37": "Samsung",
        "5C:3C:27": "Samsung",
        "94:35:0A": "Samsung",
        "A8:F2:74": "Samsung",
        # Cisco
        "00:00:0C": "Cisco",
        "00:01:42": "Cisco",
        "00:01:64": "Cisco",
        "00:1A:2F": "Cisco",
        "00:1B:D4": "Cisco",
        "00:22:BD": "Cisco",
        "00:25:45": "Cisco",
        "F4:CF:E2": "Cisco",
        # TP-Link
        "14:CC:20": "TP-Link",
        "50:C7:BF": "TP-Link",
        "54:E6:FC": "TP-Link",
        "60:E3:27": "TP-Link",
        "98:BA:5F": "TP-Link",
        "AC:84:C6": "TP-Link",
        "C0:E4:2D": "TP-Link",
        # Netgear
        "00:14:6C": "Netgear",
        "00:1B:2F": "Netgear",
        "00:1E:2A": "Netgear",
        "00:1F:33": "Netgear",
        "20:4E:7F": "Netgear",
        "9C:3D:CF": "Netgear",
        # D-Link
        "00:05:5D": "D-Link",
        "00:0D:88": "D-Link",
        "00:13:46": "D-Link",
        "00:15:E9": "D-Link",
        "00:17:9A": "D-Link",
        "00:1E:58": "D-Link",
        # Huawei (Routers, MiFi, Modems)
        "00:18:82": "Huawei",
        "00:1E:10": "Huawei",
        "00:25:9E": "Huawei",
        "00:46:4B": "Huawei",
        "04:C0:6F": "Huawei",
        "04:F9:38": "Huawei",
        "08:19:A6": "Huawei",
        "0C:96:BF": "Huawei",
        "10:44:00": "Huawei",
        "14:B9:68": "Huawei",
        "20:08:ED": "Huawei",
        "20:F3:A3": "Huawei",
        "24:09:95": "Huawei",
        "28:31:52": "Huawei",
        "2C:AB:00": "Huawei",
        "34:00:A3": "Huawei",
        "48:46:FB": "Huawei",
        "48:AD:08": "Huawei",
        "4C:8B:EF": "Huawei",
        "54:A5:1B": "Huawei",
        "58:2A:F7": "Huawei",
        "5C:C3:07": "Huawei",
        "60:DE:44": "Huawei",
        "70:72:3C": "Huawei",
        "80:B6:86": "Huawei",
        "88:CE:FA": "Huawei",
        "C8:D1:5E": "Huawei",
        "E0:24:7F": "Huawei",
        "E4:68:A3": "Huawei",
        "F4:63:1F": "Huawei",
        "F8:4A:BF": "Huawei",
        # ZTE Corporation (MiFi, Routers, Modems - very common)
        "5C:4D:BF": "ZTE",
        "00:15:EB": "ZTE",
        "00:19:C6": "ZTE",
        "00:1E:73": "ZTE",
        "00:22:93": "ZTE",
        "00:25:12": "ZTE",
        "00:26:ED": "ZTE",
        "08:18:1A": "ZTE",
        "0C:12:62": "ZTE",
        "10:D0:7A": "ZTE",
        "14:14:4B": "ZTE",
        "18:68:CB": "ZTE",
        "1C:1D:67": "ZTE",
        "20:89:84": "ZTE",
        "24:76:7D": "ZTE",
        "28:FF:3E": "ZTE",
        "2C:26:C5": "ZTE",
        "2C:95:7F": "ZTE",
        "30:D3:86": "ZTE",
        "34:4B:50": "ZTE",
        "38:D8:2F": "ZTE",
        "3C:DA:2A": "ZTE",
        "40:F4:13": "ZTE",
        "44:F4:36": "ZTE",
        "48:A7:4E": "ZTE",
        "4C:09:D4": "ZTE",
        "50:78:B3": "ZTE",
        "54:22:F8": "ZTE",
        "58:2F:40": "ZTE",
        "5C:B0:66": "ZTE",
        "60:15:92": "ZTE",
        "64:13:6C": "ZTE",
        "68:1A:B2": "ZTE",
        "6C:8B:2F": "ZTE",
        "70:9F:2D": "ZTE",
        "74:88:8B": "ZTE",
        "78:31:C1": "ZTE",
        "7C:A2:3E": "ZTE",
        "80:38:BC": "ZTE",
        "84:74:2A": "ZTE",
        "88:5D:FB": "ZTE",
        "8C:68:C8": "ZTE",
        "90:4E:2B": "ZTE",
        "94:A7:B7": "ZTE",
        "98:6C:F5": "ZTE",
        "9C:D2:4B": "ZTE",
        "A0:EC:80": "ZTE",
        "A4:A4:D3": "ZTE",
        "A8:64:F1": "ZTE",
        "AC:64:62": "ZTE",
        "B0:75:D5": "ZTE",
        "B4:B3:62": "ZTE",
        "B8:D4:E7": "ZTE",
        "BC:76:70": "ZTE",
        "C0:6A:E5": "ZTE",
        "C4:9F:4C": "ZTE",
        "C8:7B:5B": "ZTE",
        "CC:A2:23": "ZTE",
        "D0:15:4A": "ZTE",
        "D4:6A:91": "ZTE",
        "D8:55:A3": "ZTE",
        "DC:02:8E": "ZTE",
        "E0:19:54": "ZTE",
        "E0:97:96": "ZTE",
        "E4:3E:D7": "ZTE",
        "E8:B2:AC": "ZTE",
        "EC:1D:7F": "ZTE",
        "F0:84:2F": "ZTE",
        "F4:6D:E2": "ZTE",
        "F8:E8:11": "ZTE",
        "FC:2D:5E": "ZTE",
        # Alcatel (Mobile hotspots, routers)
        "00:07:72": "Alcatel",
        "00:08:2F": "Alcatel",
        "00:0E:86": "Alcatel",
        "00:14:7D": "Alcatel",
        "00:1A:F0": "Alcatel",
        "00:20:32": "Alcatel",
        "00:20:60": "Alcatel",
        "00:E0:B1": "Alcatel",
        "28:6E:D4": "Alcatel",
        "3C:81:D8": "Alcatel",
        "48:3B:38": "Alcatel",
        "5C:B4:3E": "Alcatel",
        "9C:97:26": "Alcatel",
        "D4:B2:7A": "Alcatel",
        # Tenda (Budget routers, very common)
        "C8:3A:35": "Tenda",
        "CC:B2:55": "Tenda",
        "D8:32:14": "Tenda",
        # Mikrotik (Popular ISP routers)
        "00:0C:42": "Mikrotik",
        "4C:5E:0C": "Mikrotik",
        "6C:3B:6B": "Mikrotik",
        "B8:69:F4": "Mikrotik",
        "CC:2D:E0": "Mikrotik",
        "D4:CA:6D": "Mikrotik",
        "E4:8D:8C": "Mikrotik",
        # Dell
        "00:06:5B": "Dell",
        "00:08:74": "Dell",
        "00:0B:DB": "Dell",
        "00:0D:56": "Dell",
        "00:0F:1F": "Dell",
        "00:11:43": "Dell",
        "00:14:22": "Dell",
        "18:A9:9B": "Dell",
        "B8:AC:6F": "Dell",
        # HP / HPE
        "00:01:E6": "HP",
        "00:02:A5": "HP",
        "00:0A:57": "HP",
        "00:0D:9D": "HP",
        "00:11:0A": "HP",
        "00:14:C2": "HP",
        "00:17:A4": "HP",
        "2C:27:D7": "HP",
        "3C:D9:2B": "HP",
        # Intel
        "00:02:B3": "Intel",
        "00:03:47": "Intel",
        "00:04:23": "Intel",
        "00:0E:0C": "Intel",
        "00:13:02": "Intel",
        "00:13:20": "Intel",
        "00:15:00": "Intel",
        "00:1B:21": "Intel",
        "00:1E:67": "Intel",
        # Lenovo
        "00:09:2D": "Lenovo",
        "00:1A:6B": "Lenovo",
        "00:21:5E": "Lenovo",
        "28:D2:44": "Lenovo",
        "70:72:0D": "Lenovo",
        "98:FA:9B": "Lenovo",
        # Microsoft / Xbox
        "00:03:FF": "Microsoft",
        "00:0D:3A": "Microsoft",
        "00:12:5A": "Microsoft",
        "00:15:5D": "Hyper-V",
        "00:17:FA": "Microsoft",
        "00:1D:D8": "Microsoft",
        "28:18:78": "Microsoft",
        "7C:1E:52": "Microsoft",
        # VMware
        "00:05:69": "VMware",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        # ASUS
        "00:11:D8": "ASUS",
        "00:15:F2": "ASUS",
        "00:17:31": "ASUS",
        "00:1A:92": "ASUS",
        "00:1E:8C": "ASUS",
        "00:22:15": "ASUS",
        "14:DD:A9": "ASUS",
        # Google
        "3C:5A:B4": "Google",
        "54:60:09": "Google",
        "94:EB:2C": "Google",
        "F4:F5:E8": "Google",
        # Amazon (Echo, Fire, etc.)
        "00:FC:8B": "Amazon",
        "0C:47:C9": "Amazon",
        "18:74:2E": "Amazon",
        "34:D2:70": "Amazon",
        "40:B4:CD": "Amazon",
        "68:54:FD": "Amazon",
        "74:C2:46": "Amazon",
        # Ubiquiti
        "00:27:22": "Ubiquiti",
        "04:18:D6": "Ubiquiti",
        "24:A4:3C": "Ubiquiti",
        "44:D9:E7": "Ubiquiti",
        "68:72:51": "Ubiquiti",
        "80:2A:A8": "Ubiquiti",
        "B4:FB:E4": "Ubiquiti",
        "FC:EC:DA": "Ubiquiti",
        # Aruba / HPE Aruba
        "00:0B:86": "Aruba",
        "00:1A:1E": "Aruba",
        "04:BD:88": "Aruba",
        "20:4C:03": "Aruba",
        "24:DE:C6": "Aruba",
        # Synology / NAS
        "00:11:32": "Synology",
        # QNAP
        "00:08:9B": "QNAP",
        # Sonos
        "00:0E:58": "Sonos",
        "5C:AA:FD": "Sonos",
        # Roku
        "00:0D:4B": "Roku",
        "B0:A7:37": "Roku",
        "D8:31:34": "Roku",
        # Nest / Google Nest
        "18:B4:30": "Nest",
        "64:16:66": "Nest",
        # Ring (Doorbell)
        "5C:47:5E": "Ring",
        # Wyze
        "2C:AA:8E": "Wyze",
        # Philips Hue
        "00:17:88": "Philips Hue",
        # Espressif (ESP8266/ESP32 IoT devices)
        "18:FE:34": "Espressif",
        "24:0A:C4": "Espressif",
        "30:AE:A4": "Espressif",
        "5C:CF:7F": "Espressif",
        "84:0D:8E": "Espressif",
        "A4:7B:9D": "Espressif",
        "CC:50:E3": "Espressif",
        # Xiaomi
        "00:9E:C8": "Xiaomi",
        "0C:1D:AF": "Xiaomi",
        "28:6C:07": "Xiaomi",
        "34:CE:00": "Xiaomi",
        "64:09:80": "Xiaomi",
        "78:11:DC": "Xiaomi",
        # OnePlus
        "C0:EE:FB": "OnePlus",
        # LG Electronics
        "00:05:C9": "LG",
        "00:1C:62": "LG",
        "00:1E:75": "LG",
        "10:68:3F": "LG",
        "20:21:A5": "LG",
        # Sony
        "00:01:4A": "Sony",
        "00:04:1F": "Sony",
        "00:13:A9": "Sony",
        "00:19:C5": "Sony",
        "00:1D:BA": "Sony",
        # PlayStation
        "00:D9:D1": "PlayStation",
        "28:3F:69": "PlayStation",
        # Nintendo
        "00:09:BF": "Nintendo",
        "00:17:AB": "Nintendo",
        "00:19:FD": "Nintendo",
        "00:1A:E9": "Nintendo",
        "00:1B:EA": "Nintendo",
        "00:1E:35": "Nintendo",
        "00:1F:C5": "Nintendo",
        "00:21:47": "Nintendo",
        "00:22:4C": "Nintendo",
        "00:22:AA": "Nintendo",
        "00:23:CC": "Nintendo",
        "00:24:F3": "Nintendo",
        "00:25:A0": "Nintendo",
        "34:AF:2C": "Nintendo",
        "40:D2:8A": "Nintendo",
    }

    # Fast prefix matching - check first 8 chars (XX:XX:XX format)
    prefix_8 = mac_prefix[:8].upper() if len(mac_prefix) >= 8 else mac_prefix.upper()
    if prefix_8 in vendors:
        return f" ({vendors[prefix_8]})"
    return ""


def _fingerprint_web_response(headers: dict, text: str) -> str:
    """
    Shared fingerprinting logic for web responses.
    Used by both sync and async verifiers to avoid code duplication.

    Args:
        headers: Dictionary of response headers (lowercase keys preferred)
        text: Response body text (first 5KB recommended)

    Returns:
        Comma-separated string of detected technologies
    """
    hints = []

    # Normalize headers to lowercase
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # 1. Server header
    server = headers_lower.get("server", "")
    if server:
        hints.append(_strip_ansi(server))

    # 2. Powered-By Header
    powered_by = headers_lower.get("x-powered-by", "")
    if powered_by:
        hints.append(_strip_ansi(powered_by))

    # Limit text to first 5KB for performance
    text = text[:5000] if text else ""

    # CMS Detection
    # Moodle
    if "moodle" in text.lower() or "course/view.php" in text:
        version_match = re.search(r'content="Moodle ([0-9.]+)"', text, re.IGNORECASE)
        if version_match:
            hints.append(f"Moodle {version_match.group(1)}")
        else:
            hints.append("Moodle")

    # WordPress
    if "wp-content" in text or "wordpress" in text.lower():
        hints.append("WordPress")

    # Canvas LMS
    if "canvas" in text.lower() and "instructure" in text.lower():
        hints.append("Canvas LMS")

    # Blackboard
    if "blackboard.com" in text.lower():
        hints.append("Blackboard")

    # 3. HTML Title
    title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
    if title_match:
        title = title_match.group(1).strip()[:40]  # Cap length
        hints.append(f"Title: {_strip_ansi(title)}")

    return ", ".join(hints) if hints else "Generic Web Server"


def get_local_network() -> str:
    """
    Determines the local network subnet using psutil for accurate netmask.
    """
    default_subnet = "192.168.0.0/24"

    if not psutil:
        return default_subnet

    try:
        # Get active interface that has a default gateway
        # This is a bit tricky, so we iterate through interfaces to find one with an IPv4
        # that matches our local IP.

        # simple heuristic: connect to 8.8.8.8 to find local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

        # Now look up that IP's subnet in psutil
        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    # Found it
                    netmask = addr.netmask
                    network = ipaddress.IPv4Network(
                        f"{local_ip}/{netmask}", strict=False
                    )
                    return str(network)

    except (OSError, ValueError):
        pass

    return default_subnet


class HostDiscovery:  # pylint: disable=too-few-public-methods
    """
    Performs host discovery on a given subnet.
    Prefers ARP scanning if scapy is available, otherwise uses Ping.
    """

    def __init__(self, subnet: str):
        self.subnet = subnet
        self.method = "ARP" if HAS_SCAPY else "Ping"

    def scan(
        self, max_workers: int = 50, progress_callback=None, message_callback=None
    ) -> List[str]:  # pylint: disable=too-many-locals
        """
        Scans the subnet for live hosts. Uses ARP if capable, otherwise Ping.
        """
        # Parse subnet to get list of IPs
        try:
            network = ipaddress.IPv4Network(self.subnet, strict=False)
        except ValueError:
            return []

        # Filter broadcast and network addresses (unless it's a /31 or /32 special case)
        if network.prefixlen < 31:
            hosts = [str(ip) for ip in network.hosts()]
        else:
            hosts = [str(ip) for ip in network]

        if message_callback:
            message_callback(f"[*] {self.method} Scanning {self.subnet}...")

        if self.method == "ARP":
            try:
                return self._arp_scan(hosts, progress_callback)
            except (PermissionError, OSError):
                # Fallback to Ping if ARP fails (e.g. no admin privileges)
                if message_callback:
                    message_callback(
                        "[!] ARP scan failed (permission denied). Falling back to Ping..."
                    )
                # self.method = "Ping" # Implicitly falling back for this run

        # Fallback: Ping
        return self._ping_scan(hosts, max_workers, progress_callback)

    def _arp_scan(  # pylint: disable=unused-argument
        self, hosts: List[str], progress_callback=None
    ) -> List[str]:
        """
        Performs ARP scanning using Scapy (fast local network discovery).
        """
        # pylint: disable=import-outside-toplevel,redefined-outer-name,import-error,no-name-in-module
        from scapy.all import ARP, Ether, srp

        # Build ARP request packet
        # We'll send to all hosts in one shot if subnet is small enough.
        # For large subnets, we might need chunking, but scapy is pretty fast.

        arp_request = ARP(pdst=self.subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send and receive. We use timeout=2
        # srp returns (answered, unanswered)
        answered, _ = srp(packet, timeout=2, verbose=False)

        live_hosts = []
        for _, received in answered:
            live_hosts.append(received.psrc)
            if progress_callback:
                progress_callback()

        return live_hosts

    def _ping_scan(
        self, hosts: List[str], max_workers: int, progress_callback=None
    ) -> List[str]:
        """
        Ping-based host discovery (used as fallback if ARP isn't available).
        """
        live_hosts = []

        def ping_host(ip: str) -> str:
            """Ping a single host. Returns IP if reachable, else None."""
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", "-w", "1000", ip]
            try:
                result = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                    check=False,
                )
                if result.returncode == 0:
                    return ip
            except (subprocess.TimeoutExpired, OSError):
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts}

            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    live_hosts.append(result)
                if progress_callback:
                    progress_callback()

        return live_hosts


class MacScanner:  # pylint: disable=too-few-public-methods
    """Scans and caches MAC addresses from ARP table."""

    def __init__(self):
        self.arp_cache = {}
        self._populate_arp_cache()

    def _populate_arp_cache(self):
        """Populates the ARP cache by calling system ARP command."""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                # Parse Windows ARP output
                # Example: 192.168.1.1          00-11-22-33-44-55     dynamic
                for line in result.stdout.splitlines():
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F\-]{17})", line
                    )
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).replace("-", ":").upper()
                        self.arp_cache[ip] = mac
            else:
                # Linux/Mac
                result = subprocess.run(
                    ["arp", "-n"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                # Parse Linux/Mac ARP output
                # Example: 192.168.1.1  ether   00:11:22:33:44:55   C   eth0
                for line in result.stdout.splitlines():
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+.*?([\da-fA-F:]{17})", line
                    )
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).replace("-", ":").upper()
                        self.arp_cache[ip] = mac

        except (subprocess.CalledProcessError, OSError):
            # Could not run arp or parse output on this platform
            pass

    def get_mac_info(self, ip: str) -> str:
        """
        Returns MAC address and estimated vendor (if known) for an IP.
        """
        mac = self.arp_cache.get(ip)
        if not mac:
            return ""

        # Use cached vendor lookup
        vendor = _get_vendor_from_mac(mac)
        return f"[{mac}]{vendor}"


class PortScanner:  # pylint: disable=too-few-public-methods
    """Scans a host for open ports using socket connections."""

    def __init__(self, ports: List[int]):
        self.ports = ports

    def _check_port(self, ip: str, port: int) -> int:
        """
        Checks if a specific port is open on a host.
        Returns port number if open, 0 if closed.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                return port if result == 0 else 0
        except (socket.error, OSError):
            return 0

    def scan_host(self, ip: str, parallel: bool = True) -> List[int]:
        """
        Scans all configured ports on a single host.
        Returns list of open ports.

        Args:
            ip: Target IP address
            parallel: Use parallel scanning (faster for many ports)
        """
        if parallel and len(self.ports) > 3:
            # Parallel scanning - 5-10x faster for many ports
            return self._scan_host_parallel(ip)
        # Sequential for small port lists (less overhead)
        return self._scan_host_sequential(ip)

    def _scan_host_sequential(self, ip: str) -> List[int]:
        """Sequential port scanning (low overhead for few ports)."""
        open_ports = []
        for port in self.ports:
            if self._check_port(ip, port):
                open_ports.append(port)
        return open_ports

    def _scan_host_parallel(self, ip: str) -> List[int]:
        """Parallel port scanning using ThreadPoolExecutor."""
        open_ports = []
        # Limit workers to avoid overwhelming the target
        max_workers = min(len(self.ports), 20)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port checks
            future_to_port = {
                executor.submit(self._check_port, ip, port): port for port in self.ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:  # Non-zero means port is open
                    open_ports.append(result)

        return sorted(open_ports)


class ServiceVerifier:  # pylint: disable=too-few-public-methods
    """Verifies HTTP/HTTPS services and identifies running technologies."""

    def __init__(self, check_path: str = "/", timeout: int = 3, retries: int = 3):
        self.check_path = check_path
        self.timeout = timeout
        # Normalize path
        if not self.check_path.startswith("/"):
            self.check_path = "/" + self.check_path

        # Initialize session with connection pooling and retry logic
        self.session = requests.Session()
        self.session.verify = False

        # Configure retry strategy
        retry_strategy = Retry(
            total=retries,
            backoff_factor=0.5,  # 0.5s, 1s, 2s delays
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )

        # Mount adapter with retry strategy and connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=50,  # Connection pool size
            pool_maxsize=50,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def check_http(
        self, ip: str, port: int, check_paths: List[str] = None
    ) -> Tuple[str, str, int, str]:
        """
        Checks if a web service exists.
        Returns (StatusType, URL, StatusCode, Fingerprint)
        """
        schemes = ["https", "http"] if port in [443, 8443] else ["http"]

        if check_paths is None:
            check_paths = [self.check_path]
            # If default path is not root, also check root as fallback
            if self.check_path != "/":
                check_paths.append("/")

        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"

            for path in check_paths:
                target_url = f"{base_url}{path}"
                try:
                    response = self.session.get(
                        target_url,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=False,
                    )

                    # Fingerprinting logic
                    fingerprint = self._identify_service(response)

                    if response.status_code in (200, 401, 403) or (
                        300 <= response.status_code < 400
                    ):
                        # FALSE POSITIVE CHECK: Wildcard / Soft 404 detection
                        # If we found a 200 OK, check if a random path also
                        # returns 200 OK with same content
                        if response.status_code == 200 and self._is_wildcard_response(
                            base_url, response
                        ):
                            # matches wildcard behavior -> likely just a router login page
                            # for *any* URL
                            continue

                        status_type = (
                            "FOUND" if path == self.check_path else "ROOT_ONLY"
                        )
                        # Special case: if we found Moodle explicitly in the fingerprint,
                        # upgrade confidence
                        if "Moodle" in fingerprint and status_type == "ROOT_ONLY":
                            status_type = "FOUND_MATCH"

                        return (
                            status_type,
                            target_url,
                            response.status_code,
                            fingerprint,
                        )

                except requests.RequestException:
                    # network/HTTP error for this URL - try next
                    continue

        # Nothing found
        return ("NOT_FOUND", "", 0, "")

    def _is_wildcard_response(
        self, base_url: str, original_response: requests.Response
    ) -> bool:
        """
        Checks if the server returns 200 for random paths (wildcard/soft 404).
        """
        random_path = f"/{uuid.uuid4().hex}"
        try:
            test_resp = self.session.get(
                f"{base_url}{random_path}",
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            # If random path also gives 200 and similar content length, it's a wildcard
            if (
                test_resp.status_code == 200
                and abs(len(test_resp.text) - len(original_response.text)) < 100
            ):
                return True
        except requests.RequestException:
            pass
        return False

    def _identify_service(self, response: requests.Response) -> str:
        """
        Identifies the web service/technology from response headers and body.
        """
        return _fingerprint_web_response(dict(response.headers), response.text)


# Async version for Phase 2
class AsyncServiceVerifier:  # pylint: disable=too-few-public-methods
    """Async version of ServiceVerifier using aiohttp for higher concurrency."""

    def __init__(self, check_path: str = "/", timeout: int = 3):
        self.check_path = check_path
        self.timeout = timeout
        if not self.check_path.startswith("/"):
            self.check_path = "/" + self.check_path

    async def check_http(  # pylint: disable=too-many-locals
        self, ip: str, port: int, check_paths: List[str] = None
    ) -> Tuple[str, str, int, str]:
        """
        Async checks if a web service exists.
        Returns (StatusType, URL, StatusCode, Fingerprint)
        """
        if not HAS_AIOHTTP:
            raise RuntimeError("aiohttp is required for async operations")

        schemes = ["https", "http"] if port in [443, 8443] else ["http"]

        if check_paths is None:
            check_paths = [self.check_path]
            if self.check_path != "/":
                check_paths.append("/")

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector
        ) as session:
            for scheme in schemes:
                base_url = f"{scheme}://{ip}:{port}"

                for path in check_paths:
                    target_url = f"{base_url}{path}"
                    try:
                        async with session.get(
                            target_url, allow_redirects=True
                        ) as response:
                            # Get response body
                            text = await response.text()
                            fingerprint = self._identify_service_from_text(
                                response, text
                            )

                            if response.status in (200, 401, 403) or (
                                300 <= response.status < 400
                            ):
                                # Wildcard check
                                if (
                                    response.status == 200
                                    and await self._is_wildcard_response(
                                        session, base_url, text
                                    )
                                ):
                                    continue

                                status_type = (
                                    "FOUND" if path == self.check_path else "ROOT_ONLY"
                                )
                                if (
                                    "Moodle" in fingerprint
                                    and status_type == "ROOT_ONLY"
                                ):
                                    status_type = "FOUND_MATCH"

                                return (
                                    status_type,
                                    target_url,
                                    response.status,
                                    fingerprint,
                                )

                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue

        return ("NOT_FOUND", "", 0, "")

    async def _is_wildcard_response(
        self, session: aiohttp.ClientSession, base_url: str, original_text: str
    ) -> bool:
        """Async wildcard detection."""
        random_path = f"/{uuid.uuid4().hex}"
        try:
            async with session.get(f"{base_url}{random_path}") as test_resp:
                test_text = await test_resp.text()
                if (
                    test_resp.status == 200
                    and abs(len(test_text) - len(original_text)) < 100
                ):
                    return True
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return False

    def _identify_service_from_text(
        self, response: aiohttp.ClientResponse, text: str
    ) -> str:
        """Identifies service from response using shared fingerprinting logic."""
        return _fingerprint_web_response(dict(response.headers), text)


class BannerGrabber:  # pylint: disable=too-few-public-methods
    """Grabs banners from various network services for fingerprinting."""

    @staticmethod
    def grab_banner(  # pylint: disable=too-many-return-statements,too-many-branches
        ip: str, port: int, timeout: float = 2.0
    ) -> str:
        """
        Attempts to grab a banner from a service by connecting and reading initial response.
        Returns the banner string or empty string if failed.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))

                # Send protocol-specific probes
                if port == 22:  # SSH
                    # SSH servers send banner immediately
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    return f"SSH: {_strip_ansi(banner)}"

                if port == 21:  # FTP
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    return f"FTP: {_strip_ansi(banner)}"

                if port in (3306, 3307):  # MySQL/MariaDB
                    # MySQL sends handshake immediately
                    data = sock.recv(1024)
                    try:
                        # Parse MySQL protocol version (rough)
                        if len(data) > 5 and data[4] in (9, 10):  # Protocol version
                            version_end = data.find(b"\x00", 5)
                            if version_end > 0:
                                version = data[5:version_end].decode(
                                    "utf-8", errors="ignore"
                                )
                                return f"MySQL/MariaDB: {_strip_ansi(version)}"
                    except (ValueError, UnicodeDecodeError):
                        pass
                    return "MySQL/MariaDB (Detected)"

                if port == 5432:  # PostgreSQL
                    # PostgreSQL requires SSL negotiation first
                    return "PostgreSQL (Detected)"

                if port == 6379:  # Redis
                    sock.sendall(b"INFO server\r\n")
                    response = sock.recv(4096).decode("utf-8", errors="ignore")
                    if "redis_version:" in response:
                        for line in response.split("\n"):
                            if line.startswith("redis_version:"):
                                version = line.split(":")[1].strip()
                                return f"Redis: {version}"
                    return "Redis (Detected)"

                if port == 27017:  # MongoDB
                    return "MongoDB (Detected)"

                if port == 1433:  # MSSQL
                    return "Microsoft SQL Server (Detected)"

                if port == 5672:  # RabbitMQ
                    banner = sock.recv(1024).decode("utf-8", errors="ignore")
                    if "AMQP" in banner:
                        return f"RabbitMQ: {_strip_ansi(banner.strip())}"
                    return "RabbitMQ (Detected)"

                # Generic banner grab - just read what server sends
                sock.sendall(b"\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner:
                    return _strip_ansi(banner[:100])  # Truncate long banners

        except (socket.timeout, socket.error, OSError, UnicodeDecodeError):
            pass

        return ""

    @staticmethod
    def identify_service(ip: str, port: int) -> str:
        """
        Identifies a service on given IP:port.
        Returns a descriptive string of the service.
        """
        banner = BannerGrabber.grab_banner(ip, port)

        if banner:
            return banner

        # Fallback to port-based identification if no banner
        common_ports = {
            22: "SSH",
            21: "FTP",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            110: "POP3",
            143: "IMAP",
            389: "LDAP",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            27017: "MongoDB",
        }

        return common_ports.get(port, f"Unknown service on port {port}")
