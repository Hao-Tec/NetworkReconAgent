# pylint: disable=duplicate-code
"""Scanner utilities for host discovery, MAC lookup and simple port scanning."""

import ipaddress
import socket
import subprocess
import platform
import concurrent.futures
import re
import uuid
from typing import List, Tuple

import requests
import urllib3

try:
    import psutil
except ImportError:
    psutil = None

try:
    from scapy.all import ARP, Ether, srp

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# Suppress InsecureRequestWarning from urllib3/requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    # Found our interface
                    # psutil returns netmask (e.g., 255.255.255.0)
                    network = ipaddress.IPv4Network(
                        f"{local_ip}/{addr.netmask}", strict=False
                    )
                    return str(network)

        return default_subnet

    except (OSError, ValueError):
        return default_subnet


class ArpScanner:  # pylint: disable=too-few-public-methods
    """Scans for hosts using ARP requests (faster replacement for Ping on local network)."""

    def __init__(self, subnet: str):
        self.subnet = subnet

    def scan(self, message_callback=None) -> List[str]:
        """
        Sends ARP broadcast to subnet and returns list of live IPs.
        """
        def log(msg):
            if message_callback:
                message_callback(msg)
            else:
                print(msg)

        if not HAS_SCAPY:
            log("[!] Scapy not found or failed to import. Falling back...")
            return []

        try:
            log(f"[*] ARP Scanning {self.subnet}...")
            # Create ARP request packet
            arp = ARP(pdst=self.subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Send packet and wait for response
            # timeout=2, verbose=0
            result = srp(packet, timeout=2, verbose=0)[0]

            live_hosts = []
            for _, received in result:
                live_hosts.append(received.psrc)

            return sorted(live_hosts)

        except Exception as e:  # pylint: disable=broad-exception-caught
            # Scapy might fail if no Npcap/privileges
            log(f"[!] ARP scan failed: {e}. Falling back to Ping.")
            return []


class HostDiscovery:  # pylint: disable=too-few-public-methods
    """Discovers live hosts in a network subnet using ARP (local) or Ping."""

    def __init__(self, subnet: str):
        self.subnet = subnet
        self.system = platform.system().lower()

    def _ping(self, ip: str) -> bool:
        """
        Pings an IP address to check if it's alive.
        Returns True if host responds, False otherwise.
        """
        try:
            # -n 1 for Windows, -c 1 for Unix/Linux
            count_param = "-n" if "windows" in self.system else "-c"
            # -w 1000 (ms) for Windows, -W 1 (s) for Unix/Linux
            timeout_param = "-w" if "windows" in self.system else "-W"
            timeout_value = "500" if "windows" in self.system else "1"

            # Reduce output noise by capturing stdout/stderr
            command = ["ping", count_param, "1", timeout_param, timeout_value, ip]
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return result.returncode == 0
        except OSError:
            return False

    def scan(
        self, max_workers: int = 50, progress_callback=None, message_callback=None
    ) -> List[str]:
        """
        Scans the subnet for live hosts. Uses ARP if capable, otherwise Ping.
        """

        def log(msg):
            if message_callback:
                message_callback(msg)
            else:
                print(msg)

        # Try ARP first if Scapy is available
        if HAS_SCAPY:
            # Check if subnet is manageable size for ARP (usually always is true for local)
            arp_scanner = ArpScanner(self.subnet)
            hosts = arp_scanner.scan(message_callback=message_callback)
            if hosts:
                return hosts
            # If ARP returned nothing, might be failure or remote network, fall through to Ping

        # Fallback to Ping Scanner
        live_hosts = []
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
            hosts = [str(ip) for ip in network.hosts()]

            log(f"[*] Ping Scanning {self.subnet} ({len(hosts)} IPs)...")

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_ip = {executor.submit(self._ping, ip): ip for ip in hosts}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    if future.result():
                        # print(f"[+] Host found: {ip}")
                        live_hosts.append(ip)

                    if progress_callback:
                        progress_callback()

        except ValueError as e:
            log(f"[!] Invalid subnet: {e}")

        return sorted(live_hosts)


class MacScanner:  # pylint: disable=too-few-public-methods
    """Queries ARP cache to retrieve MAC addresses and vendor information."""

    def __init__(self):
        self.arp_cache = {}
        self._refresh_arp()

    def _refresh_arp(self):
        """
        Parses 'arp -a' output to build an IP -> MAC mapping.
        """
        try:
            # Run arp -a
            output = subprocess.check_output("arp -a", shell=True).decode(
                "utf-8", errors="ignore"
            )

            # Regex to find IP and MAC: matches "192.168.x.x ... aa-bb-cc-dd-ee-ff"
            # Windows output format: Use robust regex
            pattern = re.compile(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{17})\s+"
            )

            for line in output.splitlines():
                match = pattern.search(line)
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

        # Basic OUI lookup (Top common vendors)
        vendor = ""

        # Simple hardcoded lookup for example purposes
        # In a real tool, this would be a large database
        vendors = {
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
            "98:BA:5F": "TP-Link",  # From user's log
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:15:5D": "Hyper-V",
        }

        for prefix, name in vendors.items():
            if mac.startswith(prefix):
                vendor = f" ({name})"
                break

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
                sock.settimeout(1.0)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return port
        except OSError:
            # network error connecting to socket
            return 0
        return 0

    def scan_host(self, ip: str) -> List[int]:
        """
        Scans a single host for the defined list of ports.
        """
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(self.ports), 20)
        ) as executor:
            future_to_port = {
                executor.submit(self._check_port, ip, port): port for port in self.ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result != 0:
                    open_ports.append(result)
        return sorted(open_ports)


class ServiceVerifier:  # pylint: disable=too-few-public-methods
    """Verifies HTTP/HTTPS services and identifies running technologies."""

    def __init__(self, check_path: str = "/"):
        self.check_path = check_path
        # Normalize path
        if not self.check_path.startswith("/"):
            self.check_path = "/" + self.check_path

        # Initialize session for connection pooling
        self.session = requests.Session()
        self.session.verify = False

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
                        target_url, timeout=3, allow_redirects=True, verify=False
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

        return "NONE", "", 0, ""

    def _is_wildcard_response(
        self, base_url: str, original_response: requests.Response
    ) -> bool:
        """
        Checks if the server returns similar successful responses for non-existent paths.
        Returns True if the 'original_response' is likely a False Positive (wildcard).
        """
        try:
            # Generate a random path that shouldn't exist
            random_path = f"/{uuid.uuid4()}"
            random_url = f"{base_url}{random_path}"

            random_response = self.session.get(
                random_url, timeout=3, allow_redirects=True, verify=False
            )

            # If the random path is NOT 200, then the server is normal (honest 404s)
            # So the original 200 meant something real.
            if random_response.status_code != 200:
                return False

            # If random path IS 200, the server is a "Wildcard Host" (returns 200 for everything)
            # We must compare the content to see if the original path provided unique content.

            # 1. Compare Content Length (Allow 5% variance for dynamic timestamps etc)
            orig_len = len(original_response.content)
            rand_len = len(random_response.content)

            if orig_len == 0 or rand_len == 0:
                return True  # Suspicious empty responses

            diff_percent = abs(orig_len - rand_len) / max(orig_len, rand_len)
            if diff_percent < 0.05:
                # Content length is basically the same -> Likely same page
                return True

            # 2. Compare Titles (Strongest check)
            orig_title = self._get_title(original_response.text)
            rand_title = self._get_title(random_response.text)

            if orig_title == rand_title:
                return True  # Same title -> Likely same page

            # If length differs signficantly AND title differs -> It's a Real Page
            return False

        except requests.RequestException:
            return False  # Verification failed, assume original was real to be safe

    def _get_title(self, html: str) -> str:
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _identify_service(self, response: requests.Response) -> str:
        """
        Analyzes headers and body to identify the technology and version.
        """
        hints = []
        text = response.text
        lower_text = text.lower()
        headers = response.headers

        # 1. Technology Signatures (Keyword match)
        technologies = {
            "Moodle": ["moodle", "pluginfile.php"],
            "WordPress": ["wordpress", "wp-content"],
            "Joomla": ["joomla"],
            "Drupal": ["drupal"],
            "Canvas": ["canvas", "instructure"],
            "Blackboard": ["blackboard"],
        }

        for tech, keywords in technologies.items():
            if any(k in lower_text for k in keywords):
                # Try to find version using regex
                param_str = ""
                # Moodle version regex examples: "Moodle 3.11", "var M.cfg = ... version"
                if tech == "Moodle":
                    # Look for explicit text or meta tags
                    v_match = re.search(r"Moodle (\d+(\.\d+)+)", text, re.IGNORECASE)
                    if v_match:
                        param_str = f" v{v_match.group(1)}"

                hints.append(f"{tech}{param_str}")

        # 2. Server Headers
        if "server" in headers:
            hints.append(headers["server"])
        if "x-powered-by" in headers:
            hints.append(headers["x-powered-by"])

        # 3. HTML Title
        title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).strip()[:40]  # Cap length
            hints.append(f"Title: {title}")

        return ", ".join(hints) if hints else "Generic Web Server"
