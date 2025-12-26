from rich.console import Console
from rich.table import Table
from rich.markup import escape

console = Console()

evil_string = "[bold red]MALICIOUS[/bold red]"
escaped_string = escape(evil_string)

print("--- Escaped Direct Print ---")
console.print(f"Detected: {escaped_string}")

print("\n--- Escaped Table Print ---")
table = Table(title="Scan Results")
table.add_column("Fingerprint")
table.add_row(escaped_string)
console.print(table)
