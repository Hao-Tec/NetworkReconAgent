## 2024-05-23 - Terminal Injection Protection
**Vulnerability:** Terminal Injection via ANSI escape codes. Malicious servers could inject ANSI codes into the scanner's output (e.g. via HTML Title or Server header), potentially spoofing scan results or hiding malicious output.
**Learning:** `rich.markup.escape()` only escapes Rich's internal markup tags, not raw ANSI escape sequences. A dedicated stripping function is needed for untrusted input.
**Prevention:** Implemented `_clean_text` regex sanitization in `scanner.py` to strip ANSI codes from all network-derived strings before they reach the UI or reports.
