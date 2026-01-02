## 2024-03-24 - [Terminal Injection vulnerability in Rich library usage]
**Vulnerability:** The `rich.markup.escape` function escapes markup tags but does not strip ANSI escape codes, allowing Terminal Injection from untrusted input (e.g., malicious server banners).
**Learning:** Security tools displaying raw data from untrusted sources must sanitize ANSI codes explicitly, as standard escaping libraries often focus on their own markup syntax (HTML/Rich) rather than terminal control sequences.
**Prevention:** Implement a strict `_strip_ansi` function using regex `\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])` and apply it to all network inputs before rendering to the console.
