"""Network Reconnaissance Agent CLI.

Provides a simple command line interface to discover hosts,
scan ports and verify presence of web services.
"""

import argparse
import sys
from colorama import init, Fore, Style

from scanner import (
    HostDiscovery,
    PortScanner,
    ServiceVerifier,
    get_local_network,
    MacScanner,
)


def parse_args() -> argparse.Namespace:
    """Parse and validate CLI arguments.

    Returns parsed args namespace.
    """
    parser = argparse.ArgumentParser(
        description="Scan network for specific web services."
    )
    parser.add_argument(
        "--subnet",
        help=(
            "Target subnet in CIDR notation (e.g., 192.168.0.0/24). "
            "If omitted, auto-detects local network."
        ),
    )
    parser.add_argument(
        "--ports",
        default="80,443,8080,8000,8888,3000",
        help=(
            "Comma-separated list of ports to scan (default: "
            "80,443,8080,8000,8888,3000)"
        ),
    )
    parser.add_argument(
        "--path", default="/moodle/", help="URL path to check for (default: /moodle/)"
    )
    return parser.parse_args()


def main() -> (
    None
):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Entry point for the CLI tool.

    This function initializes the environment and delegates work to
    smaller helper functions to keep complexity low for linting.
    """
    # Initialize colorama
    # Initialize colorama
    init()

    from banner import print_banner

    print_banner()

    args = parse_args()

    # Parse ports
    try:
        target_ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        print(
            Fore.RED
            + "[!] Error: Invalid port format. Please use comma-separated numbers."
            + Style.RESET_ALL
        )
        sys.exit(1)

    # Auto-detect subnet if not provided
    target_subnet = args.subnet or None
    if not target_subnet:
        print(
            Fore.YELLOW
            + "[*] No subnet specified. Auto-detecting local network..."
            + Style.RESET_ALL,
            end="",
        )
        target_subnet = get_local_network()
        print(Fore.CYAN + str(target_subnet) + Style.RESET_ALL)

    # Delegate main work to helper objects below
    discoverer = HostDiscovery(target_subnet)
    live_hosts = discoverer.scan()

    if not live_hosts:
        print(
            Fore.RED
            + "[-] No live hosts found in "
            + str(target_subnet)
            + ". Check your network connection or subnet."
            + Style.RESET_ALL
        )
        sys.exit(0)

    print(Fore.GREEN + f"[+] Found {len(live_hosts)} live hosts." + Style.RESET_ALL)

    # Initialize MAC Scanner and show basic info
    mac_scanner = MacScanner()
    for host in live_hosts:
        mac_info = mac_scanner.get_mac_info(host)
        print(f"    - {host} {Fore.CYAN}{mac_info}{Style.RESET_ALL}")

    # 2. Port Scanning & Service Verification
    print(
        "\n"
        + Fore.YELLOW
        + f"[2] Scanning ports {target_ports} and checking for '{args.path}'..."
        + Style.RESET_ALL
    )

    scanner = PortScanner(target_ports)
    verifier = ServiceVerifier(args.path)

    found_services = []
    partial_matches = []

    # Prepare list of common paths to try
    common_paths = [args.path]
    if args.path != "/moodle/":
        common_paths.append("/moodle/")
    if args.path != "/":
        common_paths.append("/")
    if "/admin/" not in common_paths:
        common_paths.append("/admin/")

    for ip in live_hosts:
        print(f"    Scanning {ip}...", end="\r")
        open_ports = scanner.scan_host(ip)

        if not open_ports:
            continue

        for port in open_ports:
            status_type, url, status_code, fingerprint = verifier.check_http(
                ip, port, check_paths=common_paths
            )

            if status_type in ("FOUND", "FOUND_MATCH"):
                print(
                    Fore.GREEN
                    + f"[SUCCESS] Found SERVICE at {url} (Status: {status_code})"
                    + Style.RESET_ALL
                )
                if fingerprint:
                    print(
                        Fore.MAGENTA
                        + f"          Detected: {fingerprint}"
                        + Style.RESET_ALL
                    )
                found_services.append((ip, url, status_code, fingerprint))
            elif status_type == "ROOT_ONLY":
                partial_matches.append((ip, url, status_code, fingerprint))

    print(Fore.YELLOW + "\n[3] Reconnaissance Complete." + Style.RESET_ALL)

    if found_services:
        summary_msg = f"\nSUMMARY: Found {len(found_services)} TARGET MATCHES:"
        print(Fore.GREEN + summary_msg + Style.RESET_ALL)
        for ip, url, status, fp in found_services:
            print(f" -> {url} [Status: {status}] | Tech: {fp}")

    if partial_matches and not found_services:
        print(
            Fore.CYAN
            + f"\nNo exact matches for '{args.path}', but found these WEB SERVERS:"
            + Style.RESET_ALL
        )
        for ip, url, status, fp in partial_matches:
            print(f" -> {url} [Status: {status}] | Tech: {fp} (Root path works)")

    if not found_services and not partial_matches:
        print(
            Fore.RED
            + f"\nNo web services found matching path '{args.path}'."
            + Style.RESET_ALL
        )
        print("However, the following hosts are alive: " + ", ".join(live_hosts))
        print("Tip: Try scanning all ports with nmap if you still can't find it.")


if __name__ == "__main__":
    main()
