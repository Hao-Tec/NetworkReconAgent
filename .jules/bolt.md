## 2025-01-20 - Connection Reuse in ServiceVerifier

**Learning:** `requests.get()` creates a new TCP connection for every call, which incurs significant overhead (DNS + TCP Handshake + SSL Handshake) when checking multiple paths on the same host.
**Action:** Always use `requests.Session()` when making multiple requests to the same host/domain to enable Keep-Alive and connection pooling. This is a low-effort, high-impact optimization for network scanning tools.

## 2025-01-20 - Misuse of lru_cache with unique arguments

**Learning:** `functools.lru_cache` provides zero benefit when the decorated function is called with unique arguments (like full MAC addresses) even if the internal logic only uses a prefix/subset of the data. This leads to cache misses on every call and redundant execution of expensive operations (like building large dictionaries).
**Action:** Pass only the necessary data (e.g., prefix, ID) to the cached function to maximize hit rate, or perform the extraction before the call. Ensure static data used in the function is defined at the module level.
