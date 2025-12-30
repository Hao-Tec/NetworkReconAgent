## 2024-03-24 - [Terminal/CSV Injection via Banners]
**Vulnerability:** Raw ANSI escape codes from service banners were being propagated to CSV reports and terminal output. This allows malicious servers to corrupt terminal displays or inject confusing data into reports (Terminal Injection/CWE-150).
**Learning:** `rich.markup.escape()` only escapes internal markup tags, NOT ANSI control sequences. Relying on it for sanitization is insufficient for external data sources like network banners.
**Prevention:** Always strip ANSI codes from untrusted network input using a regex (like `\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])`) before processing or storing.
