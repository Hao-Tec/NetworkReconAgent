## 2024-05-23 - [Robust ARP Parsing & Command Injection Prevention]
**Vulnerability:** Usage of `shell=True` in `subprocess.check_output("arp -a", shell=True)` poses a potential command injection risk, although the input was static.
**Learning:** `arp -a` output format varies significantly between Windows (`IP ... MAC`) and Linux (`? (IP) at MAC ...`). A simple regex for one fails on the other. Also, simple commands like `arp -a` do not require shell expansion and should be run as a list `["arp", "-a"]` to follow security best practices.
**Prevention:** Always use `subprocess` with a list of arguments (e.g., `["cmd", "arg"]`) and avoid `shell=True` unless absolutely necessary. When parsing system command output, test against multiple operating system formats.
