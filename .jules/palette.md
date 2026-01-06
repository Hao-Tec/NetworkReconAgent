## 2024-05-24 - [Graceful Degradation over Hard Fails]
**Learning:** The application was configured to crash immediately with a `PermissionError` when run without Admin privileges, despite claiming to support a fallback mode. This creates a hostile user experience ("you did it wrong") instead of a helpful one ("let me fix that for you"). Users expect tools to be resilient and do their best with available permissions.
**Action:** Implement automatic fallbacks for privileged operations (like raw socket scanning) to unprivileged alternatives (like Ping/Connect), informing the user of the downgrade rather than exiting.

## 2024-05-25 - [Spinners for Indeterminate States]
**Learning:** The subnet auto-detection process uses a potentially blocking network call. Using raw `print` statements creates a static feeling where the user isn't sure if the app is hanging. Replacing this with a `rich` spinner communicates that "work is happening" and maintains UI consistency.
**Action:** Use `console.status` for any blocking operation that takes > 100ms, replacing static "Doing X..." prints.
