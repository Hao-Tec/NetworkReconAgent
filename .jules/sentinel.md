# Sentinel Journal

This journal tracks critical security learnings, vulnerability patterns, and architectural gaps discovered during security reviews. It is not a change log.

## 2024-10-24 - Inconsistent Output Sanitization

**Vulnerability:** CSV Injection (Formula Injection) in report generation.
**Learning:** While a sanitization function `_sanitize_csv_cell` existed, it was only applied to the `fingerprint` field, leaving `url` and others vulnerable. This highlights the risk of selective sanitization versus default-deny or output-encoding layers.
**Prevention:** Apply sanitization logic to all user-controlled or external input fields before serialization, or use a serialization library that handles this natively (though Python's `csv` module does not prevent formula injection).
