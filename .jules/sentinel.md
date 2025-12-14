## 2024-05-23 - Command Injection Risk in ARP Scanner
**Vulnerability:** `subprocess.check_output("arp -a", shell=True)` was used to run a system command.
**Learning:** Even with static strings, `shell=True` is a dangerous pattern that can lead to command injection if the code is modified later to include variables. It's flagged by security linters and should be avoided.
**Prevention:** Always use `subprocess` with a list of arguments (e.g. `["arp", "-a"]`) and keep `shell=False` (default) unless absolutely necessary for shell features (pipes, redirects), in which case explicit validation is required.
