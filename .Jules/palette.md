## 2024-05-23 - [Blocking CLI Operations]
**Learning:** Users perceive CLI apps as "broken" during silent blocking operations like network scanning. Even if `print` statements exist, they are easily missed or look like logs.
**Action:** Wrap long-running blocking calls (like `scan()`) in `console.status` spinners. The `rich` library handles stdout gracefully, so existing print statements still work and appear above the spinner, providing a "living" log + current status. Also, always handle `KeyboardInterrupt` to avoid ugly stack traces.
