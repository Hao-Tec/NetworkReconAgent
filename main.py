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


def main():
    # Initialize colorama
    init()

    banner = f"""
    {Fore.CYAN}
    ╔══════════════════════════════════════════╗
    ║      Network Reconnaissance Agent        ║
    ║      Moodle / Web Service Finder         ║
    ╚══════════════════════════════════════════╝
    {Style.RESET_ALL}
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="Scan network for specific web services."
    )
    parser.add_argument(
        "--subnet",
        help="Target subnet in CIDR notation (e.g., 192.168.0.0/24). If omitted, auto-detects local network.",
    )
    parser.add_argument(
        "--ports",
        default="80,443,8080,8000,8888,3000",
        help="Comma-separated list of ports to scan (default: 80,443,8080,8000,8888,3000)",
    )
    parser.add_argument(
        "--path", default="/moodle/", help="URL path to check for (default: /moodle/)"
    )

    args = parser.parse_args()

    # Parse ports
    try:
        target_ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        print(
            f"{Fore.RED}[!] Error: Invalid port format. Please use comma-separated numbers.{Style.RESET_ALL}"
        )
        sys.exit(1)

    # Auto-detect subnet if not provided
    target_subnet = args.subnet
    if not target_subnet:
        print(
            f"{Fore.YELLOW}[*] No subnet specified. Auto-detecting local network...{Style.RESET_ALL} ",
            end="",
        )
        target_subnet = get_local_network()
        print(f"{Fore.CYAN}{target_subnet}{Style.RESET_ALL}")

    # 1. Host Discovery
    print(
        f"{Fore.YELLOW}[1] Starting Host Discovery on {target_subnet}...{Style.RESET_ALL}"
    )
    discoverer = HostDiscovery(target_subnet)
    live_hosts = discoverer.scan()

    if not live_hosts:
        print(
            f"{Fore.RED}[-] No live hosts found in {target_subnet}. Check your network connection or subnet.{Style.RESET_ALL}"
        )
        sys.exit(0)

    print(f"{Fore.GREEN}[+] Found {len(live_hosts)} live hosts.{Style.RESET_ALL}")

    # Initialize MAC Scanner
    mac_scanner = MacScanner()

    for host in live_hosts:
        mac_info = mac_scanner.get_mac_info(host)
        print(f"    - {host} {Fore.CYAN}{mac_info}{Style.RESET_ALL}")

    # 2. Port Scanning & Service Verification
    print(
        f"\n{Fore.YELLOW}[2] Scanning ports {target_ports} and checking for '{args.path}'...{Style.RESET_ALL}"
    )

    scanner = PortScanner(target_ports)
    verifier = ServiceVerifier(args.path)

    found_services = []
    partial_matches = []

    # Define common paths to check if the main one fails or just to be thorough
    check_paths = [args.path]

    # We will let the verifier handle the list, but we pass the primary first
    # Actually, let's explicit list here for clarity
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

        if open_ports:
            # print(f"    {ip} has open ports: {open_ports}")
            for port in open_ports:
                status_type, url, status_code, fingerprint = verifier.check_http(
                    ip, port, check_paths=common_paths
                )

                if status_type in ["FOUND", "FOUND_MATCH"]:
                    print(
                        f"{Fore.GREEN}[SUCCESS] Found SERVICE at {url} (Status: {status_code}){Style.RESET_ALL}"
                    )
                    if fingerprint:
                        print(
                            f"          {Fore.MAGENTA}Detected: {fingerprint}{Style.RESET_ALL}"
                        )
                    found_services.append((ip, url, status_code, fingerprint))
                elif status_type == "ROOT_ONLY":
                    # print(f"{Fore.CYAN}[INFO] Web Server at {url} (Status: {status_code}) but path '{args.path}' missing.{Style.RESET_ALL}")
                    partial_matches.append((ip, url, status_code, fingerprint))

    print(f"\n{Fore.YELLOW}[3] Reconnaissance Complete.{Style.RESET_ALL}")

    if found_services:
        print(
            f"\n{Fore.GREEN}SUMMARY: Found {len(found_services)} TARGET MATCHES:{Style.RESET_ALL}"
        )
        for ip, url, status, fp in found_services:
            print(f" -> {url} [Status: {status}] | Tech: {fp}")

    if partial_matches and not found_services:
        print(
            f"\n{Fore.CYAN}No exact matches for '{args.path}', but found these WEB SERVERS:{Style.RESET_ALL}"
        )
        for ip, url, status, fp in partial_matches:
            print(
                f" -> {url} [Status: {status}] | Tech: {fp} (Root path works, but '{args.path}' failed)"
            )

    if not found_services and not partial_matches:
        print(
            f"\n{Fore.RED}No web services found matching path '{args.path}'.{Style.RESET_ALL}"
        )
        print(f"However, the following hosts are alive: {', '.join(live_hosts)}")
        print("Tip: Try scanning all ports with nmap if you still can't find it.")


if __name__ == "__main__":
    main()
