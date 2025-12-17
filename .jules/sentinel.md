## 2024-03-24 - [Terminal Injection Prevention]
**Vulnerability:** Terminal Injection (CWE-150)
**Learning:** `rich.console.print` parses markup tags (like `[bold]`) by default. If untrusted input (like a server header or title) contains these tags, it can spoof UI elements or corrupt the terminal display.
**Prevention:** Always use `rich.markup.escape()` when printing untrusted strings within a formatted string to ensure they are rendered literally.
