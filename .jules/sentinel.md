## 2025-01-20 - [Symlink Overwrite Protection]
**Vulnerability:** The report generation function allowed overwriting files through symbolic links (`save_report` -> `open(filename, 'w')`). If a privileged user (Admin/Root) ran the scanner pointing to a malicious symlink, they could unintentionally overwrite critical system files (e.g., `/etc/passwd`).
**Learning:** File write operations in CLI tools running with elevated privileges must verify that the target is a regular file and not a symlink to prevent privilege escalation or unintended destruction. Standard `open()` follows symlinks by default.
**Prevention:** Always check `os.path.islink(path)` before writing to user-supplied output paths, especially in tools designed to run with elevated permissions.
