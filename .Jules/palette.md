## 2024-05-23 - [Handling ipaddress.hosts() Return Types]
**Learning:** Python's `ipaddress.ip_network().hosts()` returns a `list` for /32 (single host) networks but a `generator` for others. This inconsistency causes `TypeError: 'list' object is not an iterator` if you use `next()` directly without wrapping it in `iter()`.
**Action:** Always wrap `network.hosts()` in `iter()` when using manual iteration (like `next()`) to ensure consistent behavior across all subnet sizes.

## 2024-05-23 - [Visualizing Large Host Lists]
**Learning:** Displaying a long list of IP addresses (>10) as a raw comma-separated string or a single-column table creates a "wall of text" that is hard to scan.
**Action:** Use `rich.columns.Columns` with `Panel` elements to create a responsive grid layout. This compresses the vertical space required and makes the output much more scannable and visually appealing.
