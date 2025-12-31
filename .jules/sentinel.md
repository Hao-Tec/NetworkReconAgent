## 2024-05-23 - Terminal Injection via Banner Grabbing
**Vulnerability:** `BannerGrabber` and fingerprinting functions read raw network data and returned it without sanitization. If a malicious server sent ANSI escape codes in its banner or HTTP headers, it could manipulate the user's terminal (Terminal Injection).
**Learning:** `rich` library's `escape()` function only handles Rich's own markup tags (like `[bold]`), it DOES NOT strip ANSI escape codes. Relying solely on `escape()` is insufficient for untrusted input that might contain ANSI codes.
**Prevention:** Implement a strict `_clean_text` function using regex `r'\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])'` to strip ANSI codes from all network inputs before passing them to UI components or logs.
