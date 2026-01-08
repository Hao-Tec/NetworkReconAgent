## 2024-05-23 - OS-Aware Error Messages
**Learning:** Generic "Access Denied" messages cause user friction. By detecting the OS (Windows vs Linux) and dynamically suggesting the specific fix (`sudo ...` command vs "Run as Administrator"), we turn a blocker into an actionable step.
**Action:** Always check `platform.system()` when handling `PermissionError` in CLI tools to provide copy-pasteable solutions.
