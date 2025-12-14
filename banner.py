"""
Module for displaying the startup banner.
"""

import time
import random
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.align import Align

console = Console()


def matrix_rain(duration=3.0):
    """
    Simulates a Matrix 'digital rain' effect before tool startup.
    """
    chars = (
        "0101010101アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビ"
        "ピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッン"
    )
    colors = ["#00FF00", "#00CC00", "#008800", "#003300"]

    start_time = time.time()

    # Rain simulation using Rich Layout and Live display
    # This prevents the "scrolling" effect by using a full-screen TUI update
    layout = Layout()
    lines = []

    try:
        with Live(
            layout, console=console, screen=True, refresh_per_second=20, transient=True
        ):
            while time.time() - start_time < duration:
                line = ""
                width = console.width
                for _ in range(width):
                    if random.random() < 0.15:
                        char = random.choice(chars)
                        # Use raw space padding optimization
                        line += char
                    else:
                        line += " "

                # Print with raw styling for speed or rich text
                styled_line = Text()
                for char in line:
                    if char != " ":
                        styled_line.append(char, style=random.choice(colors))
                    else:
                        styled_line.append(" ")

                lines.append(styled_line)

                # Keep lines within screen height to prevent scrolling issues within the layout
                if len(lines) > console.height:
                    lines = lines[-console.height :]

                layout.update(Text("\n").join(lines))
                time.sleep(0.04)

    except KeyboardInterrupt:
        pass

    console.clear()


def system_breach_sequence():
    """
    Dramatic 'System Breach' progress bar sequence.
    """
    console.print("\n")
    with Progress(
        SpinnerColumn("dots12", style="bold red"),
        TextColumn("[bold red]{task.description}"),
        BarColumn(bar_width=None, style="red dim", complete_style="bold red"),
        TextColumn("[bold yellow]{task.percentage:>3.0f}%"),
        transient=True,
    ) as progress:

        task1 = progress.add_task("[bold red]BYPASSING FIREWALL", total=100)
        while not progress.finished:
            progress.update(task1, advance=random.uniform(2, 5))
            time.sleep(random.uniform(0.05, 0.15))

    console.print("[bold green]ACCESS GRANTED: FIREWALL BREACHED[/bold green]")
    time.sleep(0.5)

    with Progress(
        SpinnerColumn("aesthetic", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None, style="cyan dim", complete_style="bold cyan"),
        TextColumn("[bold cyan]{task.percentage:>3.0f}%"),
        transient=True,
    ) as progress:

        task2 = progress.add_task("[bold cyan]INJECTING PAYLOADS", total=100)
        while not progress.finished:
            progress.update(task2, advance=random.uniform(3, 8))
            time.sleep(random.uniform(0.05, 0.1))

    console.print("[bold green]SYSTEM UPLINK ESTABLISHED[/bold green]")
    time.sleep(0.5)


def print_banner():
    """
    Display the ultimate banner.
    """
    # 1. Matrix Rain
    matrix_rain(duration=2.5)

    # 2. Main Banner
    # Group lines for cleaner locals
    network_lines = [
        r"███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗",
        r"████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝",
        r"██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ ",
        r"██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ ",
        r"██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗",
        r"╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
    ]

    # RECON
    recon_lines = [
        r"██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗",
        r"██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║",
        r"██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║",
        r"██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║",
        r"██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║",
        r"╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
    ]

    network_width = max(len(line) for line in network_lines)
    recon_width = max(len(line) for line in recon_lines)

    padding = (network_width - recon_width) // 2
    pad_str = " " * max(0, padding)

    banner_text = Text()
    # NETWORK (Green)
    for line in network_lines:
        banner_text.append(line + "\n", style="bold green")

    # RECON (Cyan to contrast or White)
    for line in recon_lines:
        banner_text.append(pad_str + line + "\n", style="bold white")

    panel = Panel(
        Align.center(banner_text),
        border_style="bold green",
        title="[bold yellow]v2.1 ULTIMATE[/bold yellow]",
        subtitle=(
            "[bold red]Authorized Personnel Only[/bold red] | "
            "[dim]CODED BY The TECHMASTER[/dim]"
        ),
        padding=(1, 2),
    )

    console.print(panel)

    # 3. Breach Sequence
    system_breach_sequence()

    # 4. Metadata
    console.print(
        Align.center(
            "[bold white]TARGET:[/bold white] [red]L.O.C.A.L.N.E.T[/red]    "
            "[bold white]MODE:[/bold white] [red]OFFENSIVE RECON[/red]    "
            "[bold white]OPSEC:[/bold white] [green]ACTIVE[/green]"
        )
    )
    console.print(Align.center("[dim]Starting Analysis Engine...[/dim]"))
    console.print("\n[bold green]" + "━" * console.width + "[/bold green]\n")
