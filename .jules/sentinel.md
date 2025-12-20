## 2024-05-23 - CSV Injection Risk in Reporting
**Vulnerability:** User-controlled input (like service banners or HTTP headers) was being written directly to CSV reports without sanitization. This allows for CSV Injection (Formula Injection) where malicious cells starting with `=`, `+`, `-`, or `@` could execute code when the CSV is opened in Excel.
**Learning:** Reporting modules that export to CSV must treat all external input as untrusted, even if it comes from "scanned" services, as those services can be malicious.
**Prevention:** Sanitize all fields in CSV exports by prepending a single quote `'` if the field starts with dangerous characters (`=`, `+`, `-`, `@`).
