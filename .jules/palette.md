## 2024-05-24 - [Graceful Degradation over Hard Fails]
**Learning:** The application was configured to crash immediately with a `PermissionError` when run without Admin privileges, despite claiming to support a fallback mode. This creates a hostile user experience ("you did it wrong") instead of a helpful one ("let me fix that for you"). Users expect tools to be resilient and do their best with available permissions.
**Action:** Implement automatic fallbacks for privileged operations (like raw socket scanning) to unprivileged alternatives (like Ping/Connect), informing the user of the downgrade rather than exiting.

## 2025-05-18 - [Respecting User Time via Quiet Mode]
**Learning:** Lengthy startup animations, while visually impressive, become a significant friction point for repeat users and automated workflows.
**Action:** Implement a `--quiet` flag to bypass cosmetic delays, ensuring the tool feels professional and efficient for power users.
