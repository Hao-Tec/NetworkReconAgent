## 2025-02-18 - Terminal Injection via Rich Library
**Vulnerability:** Unsanitized user input (banners, HTTP headers, URLs) passed to `rich.console.print` or `rich.table.Table` can execute Rich Markup tags, allowing attackers to spoof scan results (e.g., coloring output to look like critical alerts or hiding text).
**Learning:** `rich` renders markup by default in strings. Trusting input from scanned services allows them to control the CLI output.
**Prevention:** Always wrap untrusted input with `rich.markup.escape()` before printing or adding to tables.
