## 2024-05-24 - [Graceful Degradation over Hard Fails]
**Learning:** The application was configured to crash immediately with a `PermissionError` when run without Admin privileges, despite claiming to support a fallback mode. This creates a hostile user experience ("you did it wrong") instead of a helpful one ("let me fix that for you"). Users expect tools to be resilient and do their best with available permissions.
**Action:** Implement automatic fallbacks for privileged operations (like raw socket scanning) to unprivileged alternatives (like Ping/Connect), informing the user of the downgrade rather than exiting.

## 2024-05-25 - [Respecting the User's Time with Quiet Mode]
**Learning:** Forcing a 2.5s "cool" animation on every run (even for quick checks or automated scripts) transforms a delightful first impression into a repetitive annoyance. UX must respect the user's intent: sometimes they want the show, but often they just want the data.
**Action:** Add a `--quiet` flag to all CLI tools that skip non-essential output/animations, making the tool suitable for both interactive exploration and automated pipelines.
