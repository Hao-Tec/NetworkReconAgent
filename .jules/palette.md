## 2024-05-23 - [Rich Panels for Empty States]
**Learning:** Users often miss "No Results" messages when they are just colored text. Wrapping them in a `rich.panel.Panel` creates a distinct visual block that draws attention and makes the "failure" state feel more like a structured report.
**Action:** Use `rich.panel.Panel` with `rich.text.Text` for all major status summaries, especially empty or error states, to improve readability and perceived quality.
