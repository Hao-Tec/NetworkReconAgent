import time
import random
import sys
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.ansi import AnsiDecoder
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.align import Align

console = Console()


def matrix_rain(duration=3.0):
    """
    Simulates a Matrix 'digital rain' effect before tool startup.
    """
    chars = "0101010101アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッン"
    colors = ["#00FF00", "#00CC00", "#008800", "#003300"]

    start_time = time.time()

    # Simple rain simulation: printing rapidly to console
    # A full TUI takeover is complex, so we cheat with fast scrolling text
    # wrapping it in a layout to keep it contained if we wanted, but direct print is "hackier"

    try:
        while time.time() - start_time < duration:
            line = ""
            for _ in range(console.width):
                if random.random() < 0.15:
                    char = random.choice(chars)
                    color = random.choice(colors)
                    # line += f"[{color}]{char}[/{color}]" # Rich parsing is too slow for matrix feel
                    # Use raw space padding optimization
                    line += char
                else:
                    line += " "

            # Print with raw styling for speed or rich text
            # We'll use rich logic but optimized
            styled_line = Text()
            for char in line:
                if char != " ":
                    styled_line.append(char, style=random.choice(colors))
                else:
                    styled_line.append(" ")

            console.print(styled_line)
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
    l1 = r"███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗"
    l2 = r"████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝"
    l3 = r"██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ "
    l4 = r"██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ "
    l5 = r"██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗"
    l6 = r"╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"

    banner_text = Text()
    for line in [l1, l2, l3, l4, l5, l6]:
        banner_text.append(line + "\n", style="bold green")

    panel = Panel(
        Align.center(banner_text),
        border_style="bold green",
        title="[bold yellow]v2.1 ULTIMATE[/bold yellow]",
        subtitle="[bold red]Authorized Personnel Only[/bold red]",
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
