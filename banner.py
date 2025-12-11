import time
import random
from rich.console import Console
from rich.style import Style


def print_banner():
    """Print the startup banner with hacker-style boot sequence."""
    console = Console()

    # ANSI Shadow / Block Style
    # NETWORK
    l1 = r"███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗"
    l2 = r"████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝"
    l3 = r"██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ "
    l4 = r"██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ "
    l5 = r"██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗"
    l6 = r"╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"

    # RECON
    l7 = r"██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    l8 = r"██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    l9 = r"██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    l10 = r"██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    l11 = r"██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    l12 = r"╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"

    # Print "NETWORK" in Gradient Cyan -> Blue
    console.print(f"[bold cyan]{l1}[/bold cyan]")
    console.print(f"[bold cyan]{l2}[/bold cyan]")
    console.print(f"[bold cyan]{l3}[/bold cyan]")
    console.print(f"[bold blue]{l4}[/bold blue]")
    console.print(f"[bold blue]{l5}[/bold blue]")
    console.print(f"[bold blue]{l6}[/bold blue]")

    # Print "RECON" in White/Grey
    console.print(f"[bold white]{l7}[/bold white]")
    console.print(f"[bold white]{l8}[/bold white]")
    console.print(f"[bold white]{l9}[/bold white]")
    console.print(f"[bold white]{l10}[/bold white]")
    console.print(f"[bold #888888]{l11}[/bold #888888]")
    console.print(f"[bold #888888]{l12}[/bold #888888]")

    console.print()

    # Hacker-style Boot Sequence
    checks = [
        "Initializing Network Interface",
        "Loading ARP Spoofer (Simulation)",
        "Bypassing Firewall Rules",
        "Connecting to DarkNet Nodes",
        "Optimizing Port Scanners",
    ]

    for check in checks:
        delay = random.uniform(0.03, 0.1)
        time.sleep(delay)  # Random fast boot feel
        console.print(f"[bold green][+][/bold green] {check}...", end="\r")
        time.sleep(0.05)
        console.print(
            f"[bold green][+][/bold green] {check}... [bold cyan]OK[/bold cyan]"
        )

    console.print()

    # Metadata Box
    console.print(
        " [bold yellow]VERSION[/bold yellow]: [red]v2.0.0[/red]   "
        " [bold yellow]BUILD[/bold yellow]: [blue]ELITE[/blue]   "
        " [bold yellow]CODED BY[/bold yellow]: [bold white]The TECHMASTER[/bold white]"
    )
    console.print(
        " [bold yellow]GITHUB[/bold yellow]:  [underline green]https://github.com/Hao-Tec/NetworkReconAgent[/underline green]"
    )
    console.print(
        " [bold yellow]SYSTEM[/bold yellow]:  [bold green]ONLINE & READY[/bold green]"
    )
    console.print()
    # Separator line
    console.print("[bold red]" + "=" * 65 + "[/bold red]")
    console.print()
