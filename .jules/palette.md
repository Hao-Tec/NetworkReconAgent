## 2024-05-24 - [Graceful Degradation over Hard Fails]
**Learning:** The application was configured to crash immediately with a `PermissionError` when run without Admin privileges, despite claiming to support a fallback mode. This creates a hostile user experience ("you did it wrong") instead of a helpful one ("let me fix that for you"). Users expect tools to be resilient and do their best with available permissions.
**Action:** Implement automatic fallbacks for privileged operations (like raw socket scanning) to unprivileged alternatives (like Ping/Connect), informing the user of the downgrade rather than exiting.

## 2024-05-24 - [Actionable Empty States]
**Learning:** Users often feel lost or discouraged when a tool returns no results, interpreting it as a failure of the tool or their configuration. Providing "Next Steps" or "Tips" in the empty state reduces frustration and guides them to the next logical action.
**Action:** Always include a "Next Steps" section in empty/zero-result states to guide the user towards success (e.g., suggesting different flags or deeper scans).
