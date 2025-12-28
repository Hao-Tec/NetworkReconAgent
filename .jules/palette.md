## 2024-05-24 - [Standardized Error States]
**Learning:** Users often miss critical error details (like "run as admin" or "install dependency") when they are buried in red text streams. Using a distinct UI component like a Panel for errors and empty states significantly improves scanning and actionability.
**Action:** Always wrap actionable error states (permissions, dependencies, input errors) in a visual container (Panel) with clear "Title", "Message", and "Tip" sections to guide the user to the fix.
