# Sentinel Journal

## 2024-05-22 - Terminal Injection Risks in Network Scanners
**Vulnerability:** ANSI escape codes in HTTP headers and service banners were being passed directly to the terminal output.
**Learning:** `rich.markup.escape()` only escapes markup tags (`[bold]`), NOT ANSI codes. Network scanners must explicitly strip ANSI codes from untrusted input to prevent terminal spoofing.
**Prevention:** Implemented a regex-based `_strip_ansi` sanitizer for all untrusted string inputs before display.
