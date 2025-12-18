## 2024-05-23 - Improved Live Hosts Display

**Learning:** When displaying potentially large lists of data in a CLI (like network scan results), a simple text list becomes unreadable. Users lose context of what the data represents (e.g., is that IP or MAC?).

**Action:** Use structured tables (like `rich.Table`) for lists > 5 items. This provides visual boundaries, headers for context, and better alignment, making the data scannable and "professional" feeling. Even for small lists, tables add a polished look that users appreciate.
