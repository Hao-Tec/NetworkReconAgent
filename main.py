"""Network Reconnaissance Agent CLI.

Provides a simple command line interface to discover hosts,
scan ports and verify presence of web services.
"""

import argparse
import sys
import concurrent.futures
import ipaddress
import logging
import asyncio
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.console import Console
from rich.table import Table
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text
from colorama import init, Fore, Style

from scanner import (
    HostDiscovery,
    PortScanner,
    ServiceVerifier,
    AsyncServiceVerifier,
    BannerGrabber,
    get_local_network,
    MacScanner,
    HAS_AIOHTTP,
)
from banner import print_banner
from reporter import save_report

console = Console()


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
        default="80,443,8080,8000,8888,3000,5000,8443,9000",
        help=(
            "Comma-separated list of ports to scan or ranges (e.g. 80,100-200). "
            "Default includes common web ports."
        ),
    )
    parser.add_argument(
        "--all-ports",
        action="store_true",
        help="Scan all ports (1-65535). DISCLAIMER: Very slow.",
    )
    parser.add_argument(
        "--path", default="/moodle/", help="URL path to check for (default: /moodle/)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable full traceback for debugging.",
    )
    parser.add_argument(
        "--output",
        help="Path to save report (e.g. report.json or report.csv).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3,
        help="HTTP request timeout in seconds (default: 3).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Number of retries for failed HTTP requests (default: 3).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=20,
        help="Maximum concurrent workers for scanning (default: 20).",
    )
    parser.add_argument(
        "--log-file",
        help="Path to save debug log file.",
    )
    parser.add_argument(
        "--async",
        action="store_true",
        dest="use_async",
        help="Use async I/O for 10-50x speed improvement (requires aiohttp).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress startup banner and animations.",
    )
    return parser.parse_args()


def process_host(  # pylint: disable=too-many-arguments,R0917
    ip: str,
    scanner: "PortScanner",
    verifier: "ServiceVerifier",
    common_paths: list,
    progress: Progress,
    scan_task,
) -> tuple:
    """
    Scans a single host for ports and services.
    Returns a tuple of (found_services, partial_matches).
    """
    local_found = []
    local_partial = []

    # Updating description in parallel can cause flickering, so we keep it static
    # progress.update(scan_task, description=f"[bold cyan]Scanning {ip}...")

    open_ports = scanner.scan_host(ip)

    if not open_ports:
        progress.advance(scan_task)
        return [], []

    for port in open_ports:
        status_type, url, status_code, fingerprint = verifier.check_http(
            ip, port, check_paths=common_paths
        )

        if status_type in ("FOUND", "FOUND_MATCH"):
            progress.console.print(
                f"[bold green][SUCCESS] Found SERVICE at {escape(url)} "
                f"(Status: {status_code})[/bold green]"
            )
            if fingerprint:
                progress.console.print(
                    f"[magenta]          Detected: {escape(fingerprint)}[/magenta]"
                )
            local_found.append((ip, port, url, status_code, fingerprint))
        elif status_type == "ROOT_ONLY":
            local_partial.append((ip, port, url, status_code, fingerprint))
        elif status_type == "NOT_FOUND":
            # HTTP didn't work, try banner grabbing for other protocols
            banner = BannerGrabber.identify_service(ip, port)
            if banner and "Unknown service" not in banner:
                progress.console.print(
                    f"[bold cyan][INFO] Found {escape(banner)} at {ip}:{port}[/bold cyan]"
                )
                # Add to partial matches with banner info
                local_partial.append((ip, port, f"{ip}:{port}", 0, banner))

    progress.advance(scan_task)
    return local_found, local_partial


async def async_process_host(  # pylint: disable=too-many-arguments,R0917,too-many-locals
    ip: str,
    scanner: "PortScanner",
    verifier: "AsyncServiceVerifier",
    common_paths: list,
    progress: Progress,
    scan_task,
    semaphore: asyncio.Semaphore,
) -> tuple:
    """
    Async version of process_host for concurrent scanning.
    Uses semaphore to limit concurrency and avoid overwhelming the network.
    """
    async with semaphore:
        local_found = []
        local_partial = []

        # Port scanning is still synchronous - we run it in thread pool
        loop = asyncio.get_event_loop()
        open_ports = await loop.run_in_executor(None, scanner.scan_host, ip)

        if not open_ports:
            progress.advance(scan_task)
            return [], []

        # HTTP checks are async
        for port in open_ports:
            status_type, url, status_code, fingerprint = await verifier.check_http(
                ip, port, check_paths=common_paths
            )

            if status_type in ("FOUND", "FOUND_MATCH"):
                progress.console.print(
                    f"[bold green][SUCCESS] Found SERVICE at {escape(url)} "
                    f"(Status: {status_code})[/bold green]"
                )
                if fingerprint:
                    progress.console.print(
                        f"[magenta]          Detected: {escape(fingerprint)}[/magenta]"
                    )
                local_found.append((ip, port, url, status_code, fingerprint))
            elif status_type == "ROOT_ONLY":
                local_partial.append((ip, port, url, status_code, fingerprint))
            elif status_type == "NOT_FOUND":
                # HTTP didn't work, try banner grabbing (run in executor since it's sync)
                loop = asyncio.get_event_loop()
                banner = await loop.run_in_executor(
                    None, BannerGrabber.identify_service, ip, port
                )
                if banner and "Unknown service" not in banner:
                    progress.console.print(
                        f"[bold cyan][INFO] Found {escape(banner)} at {ip}:{port}[/bold cyan]"
                    )
                    local_partial.append((ip, port, f"{ip}:{port}", 0, banner))

        progress.advance(scan_task)
        return local_found, local_partial


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

    args = parse_args()

    # Check async mode requirements
    if args.use_async and not HAS_AIOHTTP:
        print(
            Fore.RED
            + "[!] Async mode requires aiohttp. Install it with:"
            + "\n    pip install aiohttp"
            + Style.RESET_ALL
        )
        sys.exit(1)

    # Setup logging if requested
    if args.log_file:
        logging.basicConfig(
            filename=args.log_file,
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
        logging.info("Network Reconnaissance Agent started")
        logging.info("Arguments: %s", args)

    # Move banner here so debug args are parsed first (though banner is safe)
    # Actually, we can just print banner after parsing args, but parsing args is fast.
    if not args.quiet:
        print_banner()

    # Parse ports
    target_ports = []
    if args.all_ports:
        # Full range scan
        target_ports = list(range(1, 65536))
    else:
        try:
            for part in args.ports.split(","):
                part = part.strip()
                if "-" in part:
                    start_port, end_port = map(int, part.split("-"))
                    target_ports.extend(range(start_port, end_port + 1))
                else:
                    target_ports.append(int(part))

            # Deduplicate and sort
            target_ports = sorted(list(set(target_ports)))

        except ValueError:
            print(
                Fore.RED
                + "[!] Error: Invalid port format. Please use comma-separated "
                + "numbers or ranges (e.g. 80-90)."
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

    # Calculate total hosts for progress bar
    try:
        network = ipaddress.ip_network(target_subnet, strict=False)
        total_hosts = sum(1 for _ in network.hosts())
    except ValueError:
        total_hosts = 100  # Fallback estimate

    with Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None, style="cyan dim", complete_style="bold cyan"),
        TextColumn("[bold cyan]{task.percentage:>3.0f}%"),
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Discovering hosts in {target_subnet}...", total=total_hosts
        )

        def advance_progress():
            progress.advance(task)

        def log_message(msg):
            progress.console.print(f"[yellow]{escape(msg)}[/yellow]")

        live_hosts = discoverer.scan(
            progress_callback=advance_progress, message_callback=log_message
        )

    if not live_hosts:
        print(
            Fore.RED
            + "[-]"
            + f" No live hosts found in {target_subnet}."
            + " Check your network connection or subnet."
            + Style.RESET_ALL
        )
        sys.exit(0)

    print(Fore.GREEN + f"[+] Found {len(live_hosts)} live hosts." + Style.RESET_ALL)

    # Initialize MAC Scanner and show basic info
    mac_scanner = MacScanner()

    # Create a table for better readability of results
    host_table = Table(show_header=True, header_style="bold magenta")
    host_table.add_column("IP Address", style="green")
    host_table.add_column("MAC Address / Vendor", style="cyan")

    for host in live_hosts:
        mac_info = mac_scanner.get_mac_info(host)
        host_table.add_row(host, escape(mac_info) if mac_info else "-")

    console.print(host_table)

    # 2. Port Scanning & Service Verification
    ports_display = str(target_ports)
    if len(target_ports) > 15:
        ports_display = (
            f"[{target_ports[0]}...{target_ports[-1]}] ({len(target_ports)} ports)"
        )

    print(
        "\n"
        + Fore.YELLOW
        + f"[2] Scanning ports {ports_display} and checking for '{args.path}'..."
        + Style.RESET_ALL
    )

    scanner = PortScanner(target_ports)

    # Create verifier based on async mode
    if args.use_async:
        verifier = AsyncServiceVerifier(args.path, timeout=args.timeout)
    else:
        verifier = ServiceVerifier(
            args.path, timeout=args.timeout, retries=args.retries
        )

    found_services = []
    partial_matches = []

    # Prepare list of common paths to try
    # Prepare list of common paths to try
    common_paths = [args.path]

    # Expanded list for deep enumeration
    defaults = [
        "/",
        "/moodle/",
        "/moodle/login/",
        "/moodle/admin/",
        "/login/",
        "/admin/",
        "/wp-login.php",
        "/dashboard/",
        "/canvas/",
        "/blackboard/",
    ]

    for p in defaults:
        if p not in common_paths and args.path.rstrip("/") != p.rstrip("/"):
            common_paths.append(p)

    with Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=None, style="blue dim", complete_style="bold blue"),
        TextColumn("[bold blue]{task.percentage:>3.0f}%"),
        transient=False,
    ) as progress:

        scan_task = progress.add_task(
            "[bold cyan]Scanning hosts...", total=len(live_hosts)
        )

        # Parallel processing of hosts
        # Cap workers to avoid overwhelming network/resources
        max_workers = min(len(live_hosts), args.max_workers) or 1

        if args.use_async:
            # Async mode - 10-50x faster!
            semaphore = asyncio.Semaphore(args.max_workers)

            async def scan_all_async():
                tasks = [
                    async_process_host(
                        ip,
                        scanner,
                        verifier,
                        common_paths,
                        progress,
                        scan_task,
                        semaphore,
                    )
                    for ip in live_hosts
                ]
                return await asyncio.gather(*tasks, return_exceptions=True)

            results = asyncio.run(scan_all_async())

            for result in results:
                if isinstance(result, Exception):
                    if args.debug:
                        print(f"Generated an exception: {result}")
                else:
                    found, partial = result
                    found_services.extend(found)
                    partial_matches.extend(partial)
        else:
            # Sync mode - traditional threading
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_ip = {
                    executor.submit(
                        process_host,
                        ip,
                        scanner,
                        verifier,
                        common_paths,
                        progress,
                        scan_task,
                    ): ip
                    for ip in live_hosts
                }

                for future in concurrent.futures.as_completed(future_to_ip):
                    try:
                        found, partial = future.result()
                        found_services.extend(found)
                        partial_matches.extend(partial)
                    except Exception as exc:  # pylint: disable=broad-exception-caught
                        if args.debug:
                            print(f"Generated an exception: {exc}")

    print(Fore.YELLOW + "\n[3] Reconnaissance Complete." + Style.RESET_ALL)

    if found_services:
        table = Table(
            title=f"SUMMARY: Found {len(found_services)} TARGET MATCHES",
            border_style="green",
        )
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Technology", style="magenta")

        for ip, port, url, status, fp in found_services:
            table.add_row(escape(url), str(status), escape(fp) if fp else "")

        console.print(table)

    if partial_matches and not found_services:
        table = Table(
            title=f"No exact matches for '{args.path}', but found WEB SERVERS",
            border_style="cyan",
        )
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Technology", style="magenta")

        for ip, port, url, status, fp in partial_matches:
            escaped_fp = escape(fp) if fp else ""
            table.add_row(escape(url), str(status), f"{escaped_fp} (Root path works)")

        console.print(table)

    # Generate Report if requested
    if args.output:
        # 1. Initialize hosts map
        hosts_map = {}
        for h in live_hosts:
            hosts_map[h] = {
                "ip": h,
                "mac": mac_scanner.get_mac_info(h) or "Unknown",
                "services": [],
            }

        # 2. Add services
        all_findings = found_services + partial_matches
        for ip, port, url, status, fp in all_findings:
            if ip in hosts_map:
                hosts_map[ip]["services"].append(
                    {"port": port, "url": url, "status": status, "fingerprint": fp}
                )

        # 3. Build final data structure
        report_data = {
            "scan_info": {
                "subnet": target_subnet,
                "ports": (
                    str(target_ports) if len(target_ports) < 20 else "Range/Large List"
                ),
                "target_path": args.path,
            },
            "hosts": list(hosts_map.values()),
        }

        save_report(report_data, args.output)

    if not found_services and not partial_matches:
        no_results_text = Text()
        no_results_text.append(
            f"No web services found matching path '{args.path}'.\n\n", style="bold red"
        )
        no_results_text.append(
            "However, the following hosts are alive:\n", style="yellow"
        )
        no_results_text.append(", ".join(live_hosts) + "\n\n", style="green")
        no_results_text.append(
            "Tip: Try scanning all ports with --all-ports if you still can't find it.",
            style="italic cyan",
        )

        console.print(Panel(no_results_text, title="Scan Results", border_style="red"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user." + Style.RESET_ALL)
        sys.exit(0)
    except PermissionError:
        print(
            Fore.RED
            + "\n[!] PERMISSION ERROR: Access Denied."
            + "\n    This tool requires Administrator privileges for network scanning."
            + "\n    Please restart your terminal as Administrator."
            + Style.RESET_ALL
        )
        sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        if "--debug" in sys.argv:
            raise
        print(
            Fore.RED
            + f"\n[!] Unexpected Error: {e}"
            + "\n    Use --debug to see full traceback."
            + Style.RESET_ALL
        )
        sys.exit(1)
