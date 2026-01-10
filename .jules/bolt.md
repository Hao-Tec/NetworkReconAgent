## 2025-01-20 - Connection Reuse in ServiceVerifier

**Learning:** `requests.get()` creates a new TCP connection for every call, which incurs significant overhead (DNS + TCP Handshake + SSL Handshake) when checking multiple paths on the same host.
**Action:** Always use `requests.Session()` when making multiple requests to the same host/domain to enable Keep-Alive and connection pooling. This is a low-effort, high-impact optimization for network scanning tools.

## 2025-01-21 - Large Dictionary Literals in Functions

**Learning:** Defining a large dictionary literal inside a function causes O(N) allocation on *every* execution of that function. Even with `lru_cache`, if the cache miss rate is high (e.g., unique inputs like MAC addresses), this allocation overhead destroys performance.
**Action:** Always move constant lookup tables (like vendor databases, common ports, etc.) to module-level constants or class attributes.
