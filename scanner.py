import ipaddress
import socket
import subprocess
import platform
import requests
import concurrent.futures
import warnings
import re
from typing import List, Tuple, Dict, Optional
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_local_network() -> str:
    """
    Determines the local network subnet (assuming /24).
    """
    try:
        # Connect to a dummy external IP to get the interface IP (no data sent)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

        # Create /24 subnet string
        # e.g., 192.168.10.40 -> 192.168.10.0/24
        network = ipaddress.IPv4Interface(f"{local_ip}/24").network
        return str(network)
    except Exception:
        return "192.168.0.0/24"  # Fallback default


class HostDiscovery:
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
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except Exception:
            return False

    def scan(self, max_workers: int = 50) -> List[str]:
        """
        Scans the subnet for live hosts using thread pool.
        """
        live_hosts = []
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
            # Skip network and broadcast addresses for common /24s,
            # though iterating over .hosts() handles this for us cleanly.
            hosts = [str(ip) for ip in network.hosts()]

            print(
                f"[*] Discovering hosts in {self.subnet} ({len(hosts)} potential IPs)..."
            )

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_ip = {executor.submit(self._ping, ip): ip for ip in hosts}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    if future.result():
                        # print(f"[+] Host found: {ip}")
                        live_hosts.append(ip)

        except ValueError as e:
            print(f"[!] Invalid subnet: {e}")

        return sorted(live_hosts)


class MacScanner:
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

        except Exception as e:
            # print(f"Error refreshing ARP: {e}")
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
        oui = mac[:8]

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


class PortScanner:
    def __init__(self, ports: List[int]):
        self.ports = ports

    def _check_port(self, ip: str, port: int) -> int:
        """
        Checks if a specific port is open on a host.
        Returns port number if open, 0 if closed.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)  # 1 second timeout for port check
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return port
        except:
            pass
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


class ServiceVerifier:
    def __init__(self, check_path: str = "/"):
        self.check_path = check_path
        # Normalize path
        if not self.check_path.startswith("/"):
            self.check_path = "/" + self.check_path

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
                    response = requests.get(
                        target_url, timeout=3, allow_redirects=True, verify=False
                    )

                    # Fingerprinting logic
                    fingerprint = self._identify_service(response)

                    if response.status_code in [200, 401, 403] or (
                        response.status_code >= 300 and response.status_code < 400
                    ):
                        status_type = (
                            "FOUND" if path == self.check_path else "ROOT_ONLY"
                        )
                        # Special case: if we found Moodle explicitly in the fingerprint, upgrade confidence
                        if "Moodle" in fingerprint and status_type == "ROOT_ONLY":
                            status_type = "FOUND_MATCH"  # Found the *service* even if path was fallback

                        return (
                            status_type,
                            target_url,
                            response.status_code,
                            fingerprint,
                        )

                except requests.RequestException:
                    pass

        return "NONE", "", 0, ""

    def _identify_service(self, response: requests.Response) -> str:
        """
        Analyzes headers and body to identify the technology.
        """
        hints = []
        text = response.text.lower()
        headers = response.headers

        # Check Keywords in Body
        if "moodle" in text:
            hints.append("Moodle (Content)")
        if "apache" in text or "apache" in headers.get("Server", "").lower():
            hints.append("Apache")
        if "iis" in text or "iis" in headers.get("Server", "").lower():
            hints.append("IIS")
        if "nginx" in headers.get("Server", "").lower():
            hints.append("Nginx")
        if "php" in headers.get("X-Powered-By", "").lower():
            hints.append("PHP")

        # Check Title
        try:
            from html.parser import HTMLParser

            # Simple regex for title is often robust enough for this level of scraping
            title_match = re.search(
                "<title>(.*?)</title>", response.text, re.IGNORECASE
            )
            if title_match:
                title = title_match.group(1).strip()[:30]  # Limit length
                hints.append(f"Title: {title}")
        except:
            pass

        if not hints:
            return "Generic Web Server"

        return ", ".join(hints)
