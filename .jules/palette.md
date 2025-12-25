## 2024-05-24 - [Respecting User Attention]
**Learning:** The "Matrix Rain" and "Firewall Breach" animations, while cool for a demo, create significant friction (3-5s delay) for repeat users and potential accessibility issues for those sensitive to flashing lights. Coolness should never come at the cost of usability or accessibility.
**Action:** Implemented a `--quiet` flag to bypass animations, giving users control over the interface verbosity and speed. Future "fun" features must always have an opt-out.
