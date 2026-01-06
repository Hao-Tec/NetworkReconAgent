## 2025-01-20 - Connection Reuse in ServiceVerifier

**Learning:** `requests.get()` creates a new TCP connection for every call, which incurs significant overhead (DNS + TCP Handshake + SSL Handshake) when checking multiple paths on the same host.
**Action:** Always use `requests.Session()` when making multiple requests to the same host/domain to enable Keep-Alive and connection pooling. This is a low-effort, high-impact optimization for network scanning tools.

## 2025-01-20 - Cache Misses and Dictionary Reconstruction

**Learning:** `functools.lru_cache` keys off function arguments. If a function takes a unique ID (like a full MAC address) but only uses a prefix for lookup, it causes 100% cache misses. Additionally, defining a large dictionary *inside* a function causes it to be reconstructed on every execution (or cache miss), leading to O(N) allocation overhead.
**Action:** 1. Move large static data structures to module-level constants. 2. Pass only the necessary data (e.g., prefix) to cached functions to maximize hit rates.
