## 2024-02-14 - Terminal Injection Protection
**Vulnerability:** Terminal Injection (ANSI Escape Sequence Injection) in scan results.
**Learning:** `rich.markup.escape()` only escapes Rich markup syntax (like `[bold]`) but preserves ANSI escape codes. Malicious servers could send headers or banners containing ANSI codes to manipulate the user's terminal (e.g., hiding text, spoofing output, or executing control characters).
**Prevention:** Explicitly strip ANSI escape codes from all untrusted input (headers, banners) before passing them to the TUI library, even if using markup escaping.
