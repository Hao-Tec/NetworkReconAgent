## 2024-05-23 - [Time Estimation in CLIs]
**Learning:** Users often perceive CLI tools as "hung" if they don't see estimated time remaining for long operations.
**Action:** Always include `TimeElapsedColumn` and `TimeRemainingColumn` in `rich.progress.Progress` for network scanning or other variable-duration tasks.
