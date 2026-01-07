## 2024-05-23 - [DoS Protection via Streamed Responses]
**Vulnerability:** The scanner was vulnerable to Denial of Service (Memory Exhaustion) when scanning targets hosting large files, as it attempted to download the entire response body into memory.
**Learning:** `requests.get()` and `aiohttp.ClientResponse.text()` download the full body by default. For security tools scanning untrusted targets, this allows targets to attack the scanner.
**Prevention:** Always use `stream=True` (requests) or `read(N)` (aiohttp) and enforce a strict byte limit when inspecting response bodies for fingerprinting.
