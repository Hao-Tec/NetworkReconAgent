# pylint: disable=duplicate-code
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
    # pylint: disable=import-error,unused-import
    from scapy.all import ARP, Ether, srp

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# Suppress InsecureRequestWarning from urllib3/requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@functools.lru_cache(maxsize=256)
def _get_vendor_from_mac(mac_prefix: str) -> str:
    """
    Cached vendor lookup by MAC address prefix.
    Returns vendor name or empty string.
    """
    vendors = {
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "98:BA:5F": "TP-Link",
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:15:5D": "Hyper-V",
        "5C:4D:BF": "Unknown",  # Can add more as discovered
    }
    for prefix, name in vendors.items():
        if mac_prefix.startswith(prefix):
            return f" ({name})"
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
        hints.append(server)

    # 2. Powered-By Header
    powered_by = headers_lower.get("x-powered-by", "")
    if powered_by:
        hints.append(powered_by)

    # Limit text to first 5KB for performance
    text = text[:5000] if text else ""

    # CMS Detection
    # Moodle
    if "moodle" in text.lower() or "course/view.php" in text:
        version_match = re.search(
            r'content="Moodle ([0-9.]+)"', text, re.IGNORECASE
        )
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
        hints.append(f"Title: {title}")

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
            return self._arp_scan(hosts, progress_callback)

        # Fallback: Ping
        return self._ping_scan(hosts, max_workers, progress_callback)

    def _arp_scan(self, hosts: List[str], progress_callback=None) -> List[str]:  # pylint: disable=unused-argument
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

    def scan_host(self, ip: str) -> List[int]:
        """
        Scans all configured ports on a single host.
        Returns list of open ports.
        """
        open_ports = []
        for port in self.ports:
            if self._check_port(ip, port):
                open_ports.append(port)
        return open_ports


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
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )

        # Mount adapter with retry strategy and connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=50,  # Connection pool size
            pool_maxsize=50
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
                        target_url, timeout=self.timeout, allow_redirects=True, verify=False
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
                                if response.status == 200 and await self._is_wildcard_response(
                                    session, base_url, text
                                ):
                                    continue

                                status_type = (
                                    "FOUND" if path == self.check_path else "ROOT_ONLY"
                                )
                                if "Moodle" in fingerprint and status_type == "ROOT_ONLY":
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
    def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:  # pylint: disable=too-many-return-statements,too-many-branches
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
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    return f"SSH: {banner}"

                if port == 21:  # FTP
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    return f"FTP: {banner}"

                if port in (3306, 3307):  # MySQL/MariaDB
                    # MySQL sends handshake immediately
                    data = sock.recv(1024)
                    try:
                        # Parse MySQL protocol version (rough)
                        if len(data) > 5 and data[4] in (9, 10):  # Protocol version
                            version_end = data.find(b'\x00', 5)
                            if version_end > 0:
                                version = data[5:version_end].decode('utf-8', errors='ignore')
                                return f"MySQL/MariaDB: {version}"
                    except (ValueError, UnicodeDecodeError):
                        pass
                    return "MySQL/MariaDB (Detected)"

                if port == 5432:  # PostgreSQL
                    # PostgreSQL requires SSL negotiation first
                    return "PostgreSQL (Detected)"

                if port == 6379:  # Redis
                    sock.sendall(b"INFO server\r\n")
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    if "redis_version:" in response:
                        for line in response.split('\n'):
                            if line.startswith('redis_version:'):
                                version = line.split(':')[1].strip()
                                return f"Redis: {version}"
                    return "Redis (Detected)"

                if port == 27017:  # MongoDB
                    return "MongoDB (Detected)"

                if port == 1433:  # MSSQL
                    return "Microsoft SQL Server (Detected)"

                if port == 5672:  # RabbitMQ
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if "AMQP" in banner:
                        return f"RabbitMQ: {banner.strip()}"
                    return "RabbitMQ (Detected)"

                # Generic banner grab - just read what server sends
                sock.sendall(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner[:100]  # Truncate long banners

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
