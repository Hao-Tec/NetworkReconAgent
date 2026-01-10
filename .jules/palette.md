## 2024-03-21 - [Consistent Exit Experience]
**Learning:** Users perceive CLI tool quality based on how gracefully it fails. Raw print statements during interruption (Ctrl+C) feel jarring compared to the rest of the rich TUI.
**Action:** Always wrap `KeyboardInterrupt` and `PermissionError` in `rich.panel.Panel` to maintain visual consistency and clearly frame the reason for termination.
